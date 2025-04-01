#!/usr/bin/env python3
import boto3, argparse, json, sys
from datetime import datetime,timedelta

def main():
    p=argparse.ArgumentParser(description="Enhanced AWS resource change monitor")
    p.add_argument("--resource",required=True);p.add_argument("--days",type=int,default=7)
    p.add_argument("--use-config",action="store_true");p.add_argument("--output",choices=["text","json"],default="text")
    args=p.parse_args();start=datetime.utcnow()-timedelta(days=args.days)
    try:
        if args.use_config:
            c=boto3.client("config");hist=c.get_resource_config_history(resourceType="AWS::Lambda::Function",resourceId=args.resource,earlierTime=start,chronologicalOrder="Reverse")
            changes=hist.get("configurationItems",[])
        else:
            ct=boto3.client("cloudtrail");resp=ct.lookup_events(LookupAttributes=[{"AttributeKey":"ResourceName","AttributeValue":args.resource}],StartTime=start)
            changes=resp.get("Events",[])
        if args.output=="json":print(json.dumps(changes,default=str))
        else:
            for ch in changes:print(f"{ch['EventTime']}: {ch['EventName']}" if 'EventTime' in ch else ch)
    except Exception as e:print(f"Error: {e}",file=sys.stderr)

if __name__=="__main__":main()
