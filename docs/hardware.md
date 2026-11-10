# Hardware Requirements

## Platform

| | Requirement |
|---|---|
| Operating system | Linux. Voidwall supports no other operating system. |
| CPU architecture | x86-64 (amd64). There is no ARM build. |
| CPU level | x86-64-v3: Intel Haswell (2013) or later, or any AMD Ryzen. ONNX Runtime needs it. |
| GPU | Not used. Model guards run on the CPU. |
| Container | Docker, or another runtime that runs a Linux amd64 image. |

Voidwall checks the CPU before anything else runs. On an older CPU it stops with a
message such as:

```
error: this CPU is below the minimum x86-64-v3; missing features: avx2, fma
```

> **Not tested yet:** Docker Desktop on macOS and on Windows. On a Mac with Apple
> silicon, Docker runs the amd64 image under emulation, and the emulated CPU can be
> below x86-64-v3.

## Memory

Memory depends on the guards and on their threads. Each thread of a model guard has its
own model session, and each session keeps the memory of its largest input. So memory
grows during the first requests, and then stays at a ceiling.

Measured with the config of the image, which runs `pii`, `prompt_injection`, and
`pii_ml`. `pii` is the [regex PII guard](guards/pii-regex.md), with no model:

| CPUs for the container | Model threads | Memory when ready | Memory after load |
|---|---|---|---|
| 12 | 6 for each model guard | 1.8 GiB | 3.7 GiB |
| 4 (`--cpus=4`) | 2 for each model guard | 1.8 GiB | 2.2 GiB |
| 12, regex `pii` guard only | None | 280 MiB | 290 MiB |

"After load" is after 48 requests of 16 KB of text, 12 at a time. Plan for at least
4 GiB with the default config. A config with fewer model guards, fewer `threads`, or a
lower `max_tokens` needs less.

By default a model guard takes the CPU count divided by the number of model guards as
its threads. The CPU count follows a limit such as `docker run --cpus`. Set
`guards.<name>.threads` to fix it. See [configuration.md](configuration.md).

## Disk

| What | Size |
|---|---|
| The image | 1.1 GB |
| The default models, in the image | 0.9 GB |
| A model that you mount | The size of its files |

## Speed

A model guard runs its model on each unit that it gets, so a long body takes longer.
Time grows faster than the text: four times the text takes more than four times as long.

One measurement on one machine, AMD Ryzen 5 7600X with 12 CPUs, the config of the image,
one `/v1/scan` request at a time:

| Body | Config of the image | Regex `pii` guard only |
|---|---|---|
| 1 KB of text | 0.15 s | under 1 ms |
| 4 KB of text | 1.0 s | Not measured |
| 16 KB of text | 5.9 s | about 1 ms |

This is not a benchmark. Measure with your own traffic and hardware.

Startup takes about 10 seconds with the config of the image, while the models load.
`/readyz` answers 503 until they are loaded.
