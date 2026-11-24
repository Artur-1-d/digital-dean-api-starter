import argparse
import csv
import json
import os
import platform
import random
import subprocess
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from statistics import median, quantiles
from uuid import uuid4

from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from app.security.adapters import seal_bytes, open_bytes
from app.security.nonce import NonceSequence
from app.security.profiles import BACKENDS, KEY_BYTES

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b'digital-dean-practice-02-benchmark'.ljust(64, b'.')


def measure_batch(operation, arguments):
    if not arguments:
        raise ValueError('Empty batch')
    start = time.perf_counter_ns()
    for item in arguments:
        operation(*item)
    elapsed = time.perf_counter_ns() - start
    if elapsed <= 0:
        raise RuntimeError('Invalid elapsed time')
    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes):
    if len(series_mean_ns) != SERIES:
        raise ValueError('Five series required')
    q1, _, q3 = quantiles(series_mean_ns, n=4, method='inclusive')
    typical = median(series_mean_ns)
    return dict(median_ns=typical, iqr_ns=q3-q1,
                throughput_mib_s=size_bytes*1e9/(2**20*typical))


def run_benchmark(output_dir):
    run_id = str(uuid4())
    started = datetime.now(timezone.utc).isoformat()
    commit = subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip()
    pairs = [(b,a) for b in BACKENDS for a in KEY_BYTES]
    materials = {p:(os.urandom(KEY_BYTES[p[1]]), NonceSequence()) for p in pairs}
    rng = random.Random(2026)
    raw, results = [], []
    for size in SIZES_BYTES:
        data = os.urandom(size)
        def seal_args(pair, count):
            b,a = pair
            key, nonces = materials[pair]
            return [(b,a,key,nonces.next(),data,BENCHMARK_AAD) for _ in range(count)]
        def open_args(pair, count):
            args = []
            for b,a,key,nonce,msg,aad in seal_args(pair,count):
                ct,tag = seal_bytes(b,a,key,nonce,msg,aad)
                args.append((b,a,key,nonce,ct,tag,aad))
            return args
        for pair in pairs:
            if open_bytes(*open_args(pair,1)[0]) != data:
                raise RuntimeError('Round trip failed')
        for name, operation, prepare in [('encrypt',seal_bytes,seal_args),('decrypt',open_bytes,open_args)]:
            means = {p:[] for p in pairs}
            for pair in pairs:
                for args in prepare(pair,WARMUP):
                    operation(*args)
            order = pairs.copy()
            for index in range(1,SERIES+1):
                rng.shuffle(order)
                for b,a in order:
                    args = prepare((b,a),OPERATIONS_PER_SERIES)
                    mean = measure_batch(operation,args)
                    means[b,a].append(mean)
                    raw.append(dict(run_id=run_id,backend=b,algorithm=a,size_bytes=size,operation=name,series_index=index,operations=OPERATIONS_PER_SERIES,total_ns=round(mean*OPERATIONS_PER_SERIES),mean_ns=mean))
                    del args
            for (b,a), values in means.items():
                results.append(dict(backend=b,algorithm=a,size_bytes=size,operation=name,series_mean_ns=values,**summarize(values,size)))
            print(f'{size} bytes / {name}: complete',flush=True)
    report = dict(schema_version=1,run_id=run_id,environment=dict(cpu=platform.processor() or platform.machine(),os=platform.platform(),architecture=platform.machine(),python=platform.python_version(),cryptography=version('cryptography'),pycryptodome=version('pycryptodome'),openssl=openssl_backend.openssl_version_text(),hardware_acceleration='not independently verified',timer_resolution_seconds=time.get_clock_info('perf_counter').resolution,started_at=started,code_commit=commit),parameters=dict(sizes_bytes=list(SIZES_BYTES),warmup=WARMUP,series=SERIES,operations_per_series=OPERATIONS_PER_SERIES,aad_bytes=len(BENCHMARK_AAD),includes_cipher_creation=True,shuffle_seed=2026),results=results)
    output_dir.mkdir(parents=True,exist_ok=True)
    with (output_dir/'raw.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(raw[0]));writer.writeheader();writer.writerows(raw)
    (output_dir/'report.json').write_text(json.dumps(report,indent=2,allow_nan=False),encoding='utf-8')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    for op in ('encrypt','decrypt'):
        fig,ax=plt.subplots(figsize=(10,6))
        for b,a in pairs:
            rows=[r for r in results if (r['backend'],r['algorithm'],r['operation'])==(b,a,op)]
            y=[r['throughput_mib_s'] for r in rows]
            bounds=[quantiles(r['series_mean_ns'],n=4,method='inclusive') for r in rows]
            low=[v-r['size_bytes']*1e9/(2**20*q[2]) for v,r,q in zip(y,rows,bounds)]
            high=[r['size_bytes']*1e9/(2**20*q[0])-v for v,r,q in zip(y,rows,bounds)]
            ax.errorbar(SIZES_BYTES,y,yerr=[low,high],marker='o',capsize=3,label=f'{a} / {b}')
        ax.set_xscale('log',base=2);ax.set_xticks(SIZES_BYTES, ['1 KiB','64 KiB','1 MiB']);ax.set_ylabel('MiB/s');ax.set_title(op+' — median and transformed IQR');ax.legend(fontsize=8);ax.grid(alpha=.25);fig.tight_layout();fig.savefig(output_dir/f'{op}.png',dpi=160);plt.close(fig)
    print(f'Completed: {len(raw)} series, {len(results)} aggregates')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,required=True)
    run_benchmark(parser.parse_args().output_dir)

if __name__=='__main__':
    main()
