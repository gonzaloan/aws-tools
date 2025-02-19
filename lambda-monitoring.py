#!/usr/bin/env python3
import argparse
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _analyze_changes(events: List[Dict]) -> List[Dict]:
    """
    Analyze the changes from CloudTrail events
    """
    changes = []
    for event in events:
        try:
            change = {
                'timestamp': event['EventTime'],
                'user': event.get('Username', 'Unknown'),
                'event_type': event['EventName'],
                'event_source': event['EventSource'],
                'resources': event.get('Resources', []),
            }

            # Parse the CloudTrail event for before/after states
            if 'CloudTrailEvent' in event:
                # TODO: Implement detailed change analysis
                pass

            changes.append(change)
        except KeyError as e:
            logger.warning(f"Skipping malformed event: {e}")
            continue

    return changes


class AWSResourceMonitor:
    def __init__(self, resource_identifier: str, days: int, include_related: bool = False):
        """
        Initialize the AWS Resource Monitor

        Args:
            resource_identifier (str): Resource ARN or name
            days (int): Number of days to look back
            include_related (bool): Whether to include related resources
        """
        self.resource_identifier = resource_identifier
        self.days = days
        self.include_related = include_related
        self.session = boto3.Session()
        self.cloudtrail = self.session.client('cloudtrail')
        self.start_time = datetime.utcnow() - timedelta(days=days)

    def _get_resource_arn(self) -> str:
        """Convert resource identifier to ARN if needed"""
        if self.resource_identifier.startswith('arn:'):
            return self.resource_identifier

        # TODO: Implement ARN construction based on resource type
        return self.resource_identifier

    def _get_resource_type(self) -> str:
        """Determine the AWS resource type from the identifier"""
        if 'lambda' in self.resource_identifier.lower():
            return 'lambda'
        # Add more resource type detection logic
        return 'unknown'

    def _get_cloudtrail_events(self) -> List[Dict]:
        """
        Retrieve CloudTrail events for the resource
        """
        try:
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')

            for page in paginator.paginate(
                    StartTime=self.start_time,
                    LookupAttributes=[{
                        'AttributeKey': 'ResourceName',
                        'AttributeValue': self.resource_identifier
                    }]
            ):
                events.extend(page.get('Events', []))

            return events
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail events: {e}")
            return []

    def analyze(self) -> Dict:
        """
        Main analysis method to detect and report changes
        """
        resource_arn = self._get_resource_arn()
        resource_type = self._get_resource_type()

        # Get main resource changes
        events = self._get_cloudtrail_events()
        changes = _analyze_changes(events)

        # Initialize the report
        report = {
            'resource_identifier': self.resource_identifier,
            'analysis_period_days': self.days,
            'analysis_time': datetime.utcnow().isoformat(),
            'changes': changes,
            'related_resources': []
        }

        if self.include_related:
            # TODO: Implement related resource analysis
            pass

        return report


def main():
    parser = argparse.ArgumentParser(description='Monitor AWS resource changes')
    parser.add_argument('--resource', required=True, help='Resource ARN or name')
    parser.add_argument('--d', type=int, default=7, help='Number of days to look back')
    parser.add_argument('--include-related', action='store_true',
                        help='Include related resource changes')

    args = parser.parse_args()

    try:
        monitor = AWSResourceMonitor(
            resource_identifier=args.resource,
            days=args.d,
            include_related=args.include_related
        )

        report = monitor.analyze()

        # TODO: Implement better report formatting
        print(f"Changes for {args.resource} in the last {args.d} days:")
        for change in report['changes']:
            print(f"\n{change['timestamp']} - {change['event_type']}")
            print(f"By: {change['user']}")
            print(f"Source: {change['event_source']}")

    except Exception as e:
        logger.error(f"Error analyzing resource: {e}")
        raise


if __name__ == "__main__":
    main()