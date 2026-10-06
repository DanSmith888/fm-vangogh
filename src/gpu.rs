//! GPU cracker: PBKDF2-HMAC-SHA1 on the GPU (wgpu + WGSL), AES trial-decrypt and
//! the correctness check on the CPU. One shader runs on Metal (macOS) and Vulkan
//! (NVIDIA/Linux), so a single binary covers both.

use anyhow::{anyhow, Result};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use wgpu::util::DeviceExt;

use crate::crack::{candidates, Opts};
use crate::ear;

const BATCH: usize = 32768; // candidates per GPU dispatch
const MAX_PW_BYTES: usize = 64; // UTF-16LE length cap for the GPU path (32 chars)
const WORDS_PER_PW: usize = 16; // 64 bytes

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Params {
    salt: [u32; 4],
    n_iter: u32,
    count: u32,
    _pad: [u32; 2],
}

struct Gpu {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
}

impl Gpu {
    fn new() -> Result<Self> {
        let instance = wgpu::Instance::default();
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: None,
            apply_limit_buckets: false,
        }))
        .map_err(|e| anyhow!("no GPU adapter: {e}"))?;
        if adapter.get_info().device_type == wgpu::DeviceType::Cpu {
            return Err(anyhow!("no hardware GPU (only a software adapter); use the CPU engine"));
        }

        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("vangogh"),
            required_features: wgpu::Features::empty(),
            required_limits: adapter.limits(),
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
            memory_hints: wgpu::MemoryHints::Performance,
            trace: wgpu::Trace::Off,
        }))
        .map_err(|e| anyhow!("request_device failed: {e}"))?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("pbkdf2"),
            source: wgpu::ShaderSource::Wgsl(include_str!("../shaders/pbkdf2.wgsl").into()),
        });

        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: None,
            entries: &[
                bgl_entry(0, true),
                bgl_entry(1, false),
                bgl_entry(2, false),
                bgl_entry_rw(3),
            ],
        });
        let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: None,
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("pbkdf2"),
            layout: Some(&pl),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(Gpu { device, queue, pipeline, layout })
    }

    /// Derive keys for a batch of passwords (each <= MAX_PW_BYTES UTF-16LE bytes).
    fn derive(&self, salt: &[u8], batch: &[String]) -> Result<Vec<[u8; 32]>> {
        let count = batch.len();
        let mut pw_words = vec![0u32; count * WORDS_PER_PW];
        let mut lens = vec![0u32; count];
        for (i, s) in batch.iter().enumerate() {
            let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            lens[i] = bytes.len() as u32;
            for (j, &b) in bytes.iter().enumerate() {
                pw_words[i * WORDS_PER_PW + j / 4] |= (b as u32) << (8 * (j % 4));
            }
        }

        let mut salt4 = [0u32; 4];
        for (k, w) in salt4.iter_mut().enumerate() {
            let mut v = 0u32;
            for t in 0..4 {
                v |= (salt[k * 4 + t] as u32) << (8 * t);
            }
            *w = v;
        }
        let params = Params { salt: salt4, n_iter: ear::KDF_ITER, count: count as u32, _pad: [0; 2] };

        let params_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: None,
            contents: bytemuck::bytes_of(&params),
            usage: wgpu::BufferUsages::UNIFORM,
        });
        let pw_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: None,
            contents: bytemuck::cast_slice(&pw_words),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let len_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: None,
            contents: bytemuck::cast_slice(&lens),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let out_size = (count * 8 * 4) as u64;
        let out_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: out_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: out_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: None,
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: params_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: pw_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: len_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 3, resource: out_buf.as_entire_binding() },
            ],
        });

        let mut enc = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = enc.begin_compute_pass(&Default::default());
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind, &[]);
            let groups = ((count as u32) + 63) / 64;
            pass.dispatch_workgroups(groups, 1, 1);
        }
        enc.copy_buffer_to_buffer(&out_buf, 0, &staging, 0, out_size);
        self.queue.submit(Some(enc.finish()));

        let slice = staging.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        self.device.poll(wgpu::PollType::Wait { submission_index: None, timeout: None }).ok();
        rx.recv()??;

        let data = slice.get_mapped_range().map_err(|e| anyhow!("map range: {e:?}"))?;
        let words: &[u32] = bytemuck::cast_slice(&data[..]);
        let mut keys = vec![[0u8; 32]; count];
        for i in 0..count {
            for k in 0..8 {
                keys[i][k * 4..k * 4 + 4].copy_from_slice(&words[i * 8 + k].to_le_bytes());
            }
        }
        drop(data);
        staging.unmap();
        Ok(keys)
    }
}

fn bgl_entry(binding: u32, uniform: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: if uniform {
                wgpu::BufferBindingType::Uniform
            } else {
                wgpu::BufferBindingType::Storage { read_only: true }
            },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

fn bgl_entry_rw(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only: false },
            has_dynamic_offset: false,
            min_binding_size: None,
        },
        count: None,
    }
}

/// The backend+name and driver string of the adapter the GPU engine will use.
/// None when there is no usable adapter. Used to show the engine over two header
/// lines (the name is long, so the driver goes on its own line).
pub fn header_engine() -> Option<(String, String)> {
    let instance = wgpu::Instance::default();
    let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
        power_preference: wgpu::PowerPreference::HighPerformance,
        force_fallback_adapter: false,
        compatible_surface: None,
        apply_limit_buckets: false,
    }))
    .ok()?;
    let i = adapter.get_info();
    if i.device_type == wgpu::DeviceType::Cpu {
        return None;
    }
    let engine = format!("{:?}: {}", i.backend, i.name);
    let driver = format!("{} {}", i.driver, i.driver_info).trim().to_string();
    Some((engine, driver))
}

/// List the GPU adapters wgpu can see, with backend and device type. Used by the
/// `devices` command so you can tell what the tool will run on.
pub fn devices() -> Vec<String> {
    let instance = wgpu::Instance::default();
    let mut out = Vec::new();
    for a in pollster::block_on(instance.enumerate_adapters(wgpu::Backends::all())) {
        let i = a.get_info();
        let driver = format!("{} {}", i.driver, i.driver_info);
        let driver = driver.trim();
        if driver.is_empty() {
            out.push(format!("{:?}: {} ({:?})", i.backend, i.name, i.device_type));
        } else {
            out.push(format!("{:?}: {} ({:?}); driver: {}", i.backend, i.name, i.device_type, driver));
        }
    }
    out
}

/// Public helper used by tests: derive keys on the GPU for the given passwords.
pub fn derive_keys_gpu(salt: &[u8], passwords: &[String]) -> Result<Vec<[u8; 32]>> {
    let gpu = Gpu::new()?;
    let mut out = Vec::with_capacity(passwords.len());
    for chunk in passwords.chunks(BATCH) {
        out.extend(gpu.derive(salt, chunk)?);
    }
    Ok(out)
}

/// Verify a batch of (password, key) pairs on the CPU: cheap gate, then confirm.
fn find_hit(data: &[u8], batch: &[String], keys: &[[u8; 32]]) -> Option<String> {
    (0..batch.len())
        .into_par_iter()
        .find_map_any(|i| {
            if ear::gate_ok(data, &keys[i]) && ear::looks_right(data, &keys[i]) {
                Some(batch[i].clone())
            } else {
                None
            }
        })
}

/// GPU-accelerated crack: PBKDF2 on the GPU, confirm on the CPU.
pub fn crack_gpu(
    data: &[u8],
    salt: &[u8],
    words: &[String],
    hint: Option<&str>,
    opts: &Opts,
) -> Result<Option<String>> {
    let counter = AtomicU64::new(0);
    crack_gpu_with(data, salt, words, hint, opts, &counter)
}

/// Like `crack_gpu`, but increments `counter` as candidates are processed so a
/// caller can display live progress.
pub fn crack_gpu_with(
    data: &[u8],
    salt: &[u8],
    words: &[String],
    hint: Option<&str>,
    opts: &Opts,
    counter: &AtomicU64,
) -> Result<Option<String>> {
    let gpu = Gpu::new()?;
    let mut batch: Vec<String> = Vec::with_capacity(BATCH);
    let mut long: Vec<String> = Vec::new();

    for pw in candidates(words, hint, opts) {
        // GPU path caps password length; longer ones (rare) go to the CPU.
        if pw.encode_utf16().count() * 2 <= MAX_PW_BYTES {
            batch.push(pw);
        } else {
            long.push(pw);
        }
        if batch.len() >= BATCH {
            let keys = gpu.derive(salt, &batch)?;
            counter.fetch_add(batch.len() as u64, Ordering::Relaxed);
            if let Some(hit) = find_hit(data, &batch, &keys) {
                return Ok(Some(hit));
            }
            batch.clear();
        }
        if long.len() >= 4096 {
            counter.fetch_add(long.len() as u64, Ordering::Relaxed);
            if let Some(hit) = long.par_iter().find_any(|p| ear::check_password(data, salt, p)) {
                return Ok(Some(hit.clone()));
            }
            long.clear();
        }
    }
    if !batch.is_empty() {
        let keys = gpu.derive(salt, &batch)?;
        counter.fetch_add(batch.len() as u64, Ordering::Relaxed);
        if let Some(hit) = find_hit(data, &batch, &keys) {
            return Ok(Some(hit));
        }
    }
    counter.fetch_add(long.len() as u64, Ordering::Relaxed);
    if let Some(hit) = long.par_iter().find_any(|p| ear::check_password(data, salt, p)) {
        return Ok(Some(hit.clone()));
    }
    Ok(None)
}
