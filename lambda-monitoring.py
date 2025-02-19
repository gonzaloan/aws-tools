#!/usr/bin/env python3
import argparse
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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

    def _is_relevant_event(self, event: Dict) -> bool:
        """
        Filter out non-relevant events
        """
        # List of events to ignore
        ignored_events = {
            'AssumeRole',
            'ConsoleLogin',
            'BatchGetTraces',
            'StartQueryExecution',
            'GetQueryExecution',
            'GetQueryResults',
            'ListTags',
            'GetFunction',  # Ignore read-only operations
            'DescribeFunction',
            'GetPolicy',
            'GetRolePolicy'
        }

        if event['EventName'] in ignored_events:
            return False

        # Ignore read-only API calls (usually start with 'Get', 'List', 'Describe')
        if event['EventName'].startswith(('Get', 'List', 'Describe', 'Head')):
            return False

        return True

    def _get_user_info(self, event: Dict) -> str:
        """
        Extract meaningful user information from the event
        """
        user_identity = event.get('UserIdentity', {})

        # Try to get the most meaningful user identifier
        if 'sessionContext' in user_identity:
            session_context = user_identity['sessionContext']
            if 'sessionIssuer' in session_context:
                return f"{session_context['sessionIssuer'].get('userName', 'Unknown')} via {user_identity.get('type', 'Unknown')}"

        # Check for different types of identities
        if user_identity.get('type') == 'IAMUser':
            return user_identity.get('userName', 'Unknown IAM User')
        elif user_identity.get('type') == 'AssumedRole':
            role_info = user_identity.get('arn', '').split('/')
            return f"Role: {role_info[-1] if len(role_info) > 1 else 'Unknown Role'}"
        elif user_identity.get('type') == 'Root':
            return 'AWS Root User'

        return user_identity.get('userName', 'Unknown')

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
                for event in page.get('Events', []):
                    if self._is_relevant_event(event):
                        events.append(event)

            return events
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail events: {e}")
            return []

    def _analyze_changes(self, events: List[Dict]) -> List[Dict]:
        """
        Analyze the changes from CloudTrail events
        """
        changes = []
        for event in events:
            try:
                # Get meaningful user information
                user = self._get_user_info(event)

                # Extract request parameters and response elements
                event_detail = event.get('CloudTrailEvent', {})
                if isinstance(event_detail, str):
                    import json
                    event_detail = json.loads(event_detail)

                request_params = event_detail.get('requestParameters', {})
                response_elements = event_detail.get('responseElements', {})

                # Create base change object
                change = {
                    'timestamp': event['EventTime'],
                    'user': user,
                    'event_type': event['EventName'],
                    'event_source': event['EventSource'],
                    'changes': self._extract_meaningful_changes(
                        event['EventName'],
                        request_params,
                        response_elements
                    )
                }

                # Only add changes that have meaningful information
                if change['changes']:
                    changes.append(change)

            except KeyError as e:
                logger.warning(f"Skipping malformed event: {e}")
                continue

        return changes

    def _extract_meaningful_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """
        Extract meaningful changes based on the event type
        """
        changes = {}

        # Handle Lambda specific changes
        if 'UpdateFunctionConfiguration' in event_name:
            if 'memorySize' in request_params:
                changes['memory'] = f"Changed to {request_params['memorySize']}MB"
            if 'timeout' in request_params:
                changes['timeout'] = f"Changed to {request_params['timeout']}s"
            if 'environment' in request_params:
                changes['environment'] = "Environment variables modified"

        elif 'UpdateFunctionCode' in event_name:
            changes['code'] = "Function code updated"
            if 'revisionId' in response_elements:
                changes['revision'] = f"New revision: {response_elements['revisionId']}"

        elif 'AddPermission' in event_name or 'RemovePermission' in event_name:
            changes['permissions'] = "Function permissions modified"

        # Add more event types as needed

        return changes

    def analyze(self) -> Dict:
        """
        Main analysis method to detect and report changes
        """
        resource_arn = self._get_resource_arn()
        resource_type = self._get_resource_type()

        # Get main resource changes
        events = self._get_cloudtrail_events()
        changes = self._analyze_changes(events)

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

        print(f"\nChanges for {args.resource} in the last {args.d} days:")
        if not report['changes']:
            print("\nNo significant changes detected.")
        else:
            for change in report['changes']:
                print(f"\n[{change['timestamp']}]")
                print(f"Action: {change['event_type']}")
                print(f"By: {change['user']}")

                if change.get('changes'):
                    print("Changes detected:")
                    for change_type, change_desc in change['changes'].items():
                        print(f"  - {change_type}: {change_desc}")

    except Exception as e:
        logger.error(f"Error analyzing resource: {e}")
        raise


if __name__ == "__main__":
    main()