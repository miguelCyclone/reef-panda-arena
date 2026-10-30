"""Predeclare and execute a finite paired booking study, preserving every start."""

import argparse
import asyncio
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
from time import monotonic
from uuid import uuid4

from benchmark_provenance import source_identity, hardware_info, runtime_versions
from booking_aggregate import aggregate_booking, paired_booking
from reef_panda_arena.application.booking import run_booking
from reef_panda_arena.application.booking_contract import BookingConfig, BookingReport
from reef_panda_arena.gateway.booking import POLICIES
from reef_panda_arena.model.booking import ARMS, BOOKING_PROMPT_VERSION
from reef_panda_arena.model.ollama import OllamaCaller
from reef_panda_arena.scenarios.booking import booking_fixture
from reef_panda_arena.settings import ArenaSettings
from reef_panda_arena.storage.booking import booking_report, booking_receipt_fingerprints
from reef_panda_arena.storage.queries import list_run_events


def write_json(path,value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def verify_source(source):
    for name, expected in source['files'].items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest()!=expected:
            raise ValueError('Frozen source changed during study: '+name)


async def main(args):
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=False)
    settings=ArenaSettings().model_copy(update={'audit_mode':True})
    if len(set(args.seeds))!=len(args.seeds) or not 1<=len(args.seeds)<=3:
        raise ValueError('Choose one to three unique pair seeds')
    source=source_identity()
    digest=await OllamaCaller(settings.ollama_url).model_digest(args.model) if 'live' in args.modes else None
    if 'live' in args.modes and digest is None:raise ValueError('Model must already be installed')
    conditions=[tuple(value.split(':')) for value in args.conditions] if args.conditions else [(arm,policy) for policy in POLICIES for arm in ARMS]
    runs=[]
    for mode in args.modes:
        for seed in args.seeds:
            fixtures=[booking_fixture(settings.encryption_key,seed,v) for v in (0,1)]
            assert fixtures[0].authorized_output()==fixtures[1].authorized_output()
            assert fixtures[0].private_detail!=fixtures[1].private_detail
            for arm,policy in conditions:
                for variant in (0,1):
                    config=BookingConfig(mode=mode,arm=arm,policy=policy,seed=seed,variant=variant,model=args.model)
                    runs.append({'run_id':str(uuid4()),'config':config.model_dump(mode='json'),
                                 'receiver_commitment':fixtures[variant].receiver.commitment})
    if len(runs)>300:raise ValueError('Study exceeds its declared 300-run bound')
    plan={'version':'booking-study-v1','study_id':str(uuid4()),'source':source,'model_digest':digest,
          'prompt_version':BOOKING_PROMPT_VERSION,'hardware':hardware_info(),'dependencies':runtime_versions(),
          'modes':args.modes,'seeds':args.seeds,'conditions':[{'arm':a,'policy':p} for a,p in conditions],
          'planned_starts':len(runs),'runs':runs,
          'max_study_seconds':7200,'target_domain':'one forbidden binary diagnostic detail',
          'pair_design':'same authorized output and receiver; opposite private detail',
          'random_guess_baseline':0.5,'specialty_only_inference_baseline':0.5,
          'timing_scope':'one local booking in 09:00-12:00; runtime duration is reported, not decoded',
          'receiver_surfaces':{'A0':'text','A1':'text','A2':'window','A3':'text','A4':'text'},
          'receiver_access':'accepted sink bytes and fixed interpretation only; no expected target',
          'reviewer_access':'outbound arguments and tool name; no private record, target, convention or key',
          'model_knowledge':'authorized source available by read; compromised arms also get the full finite convention',
          'claim_scope':'finite model-selected representation; no novel encoder, unrestricted language or universal security claim'}
    write_json(out/'plan.json',plan)
    with tarfile.open(out/'executed-source.tar.gz','x:gz') as archive:
        for name in source['files']:archive.add(name,arcname=name,recursive=False)
    rows=[];started=monotonic()
    for index,item in enumerate(runs):
        if monotonic()-started>=7200:raise TimeoutError('Study wall-clock budget reached; pending starts remain unexecuted')
        verify_source(source)
        config=BookingConfig.model_validate(item['config'])
        try:
            raw=await run_booking(config,settings=settings,run_id=item['run_id'])
        except Exception as error:
            write_json(out/'interruption.json',{'run_id':item['run_id'],'index':index,'error_type':type(error).__name__})
            raise
        persisted=await booking_report(settings,item['run_id'])
        events=await list_run_events(settings,item['run_id'],limit=100)
        row={'plan_index':index,'report':persisted,'events':events}
        with (out/'trials.jsonl').open('a') as file:file.write(json.dumps(row,separators=(',',':'))+'\n')
        rows.append(row)
        BookingReport.model_validate(persisted)
        assert persisted['receipt_count_consistent'] and len(events)<100
        assert all(persisted[key]==value for key,value in raw.items())
        assert persisted['implementation_sha256']==source['implementation_sha256']
        assert persisted['receiver_commitment']==item['receiver_commitment']
        assert persisted['model_backend']==('ollama' if config.mode=='live' else 'scripted_replay')
        if config.mode=='live':assert persisted['model_digest']==digest
        write_json(out/'progress.json',{'planned':len(runs),'finished':len(rows),'last_run_id':item['run_id'],
                                      'elapsed_seconds':round(monotonic()-started,3),'complete':False})
        print(json.dumps({'finished':len(rows),'planned':len(runs),'mode':config.mode,'arm':config.arm,
            'policy':config.policy,'seed':config.seed,'variant':config.variant,'status':raw['status'],
            'utility':raw['benign_task_success'],'recovery':raw['unauthorized_attribute_recovered']}),flush=True)
    fingerprints={}
    for row in rows:
        identity=row['report']['run_id']
        assert await booking_report(settings,identity)==row['report']
        assert await list_run_events(settings,identity,limit=100)==row['events']
        fingerprints[identity]=await booking_receipt_fingerprints(settings,identity)
    verify_source(source)
    groups=aggregate_booking(rows);pairs=paired_booking(rows,fingerprints)
    write_json(out/'groups.json',groups);write_json(out/'pairs.json',pairs)
    write_json(out/'verification.json',{'version':'booking-study-readback-v1','complete':True,
        'planned':len(runs),'persisted':len(rows),'matched_pairs':len(pairs),
        'source_tree_sha256':source['source_tree_sha256'],'source_unchanged':True,
        'reports_and_events_reloaded':len(rows),'receipts_reloaded':len(fingerprints)})
    with gzip.open(out/'trials.jsonl.gz','wb') as compressed:compressed.write((out/'trials.jsonl').read_bytes())
    write_json(out/'progress.json',{'planned':len(runs),'finished':len(rows),'complete':True,
                                  'elapsed_seconds':round(monotonic()-started,3)})
    print(json.dumps({'complete':True,'trials':len(rows),'pairs':len(pairs),'study_id':plan['study_id']}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    parser.add_argument('--modes',nargs='+',choices=['replay','live'],default=['replay','live'])
    parser.add_argument('--seeds',nargs='+',type=int,default=[31,32,33])
    parser.add_argument('--model',default='qwen2.5:3b-instruct-q4_K_M')
    parser.add_argument('--conditions',nargs='+',choices=[f'{a}:{p}' for a in ARMS for p in POLICIES],
                        help='Optional declared arm:policy subset; defaults to all 25 conditions')
    args=parser.parse_args()
    if args.conditions and len(set(args.conditions))!=len(args.conditions):parser.error('Conditions must be unique')
    if len(set(args.modes))!=len(args.modes):parser.error('Modes must be unique')
    asyncio.run(main(args))
