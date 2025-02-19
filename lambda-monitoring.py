#!/usr/bin/env python3
import argparse
import json

import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from botocore.exceptions import ClientError
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AWSResourceMonitor:
    RESOURCE_TYPE_COLORS = {
        'lambda': Fore.BLUE,
        'subnet': Fore.GREEN,
        'security_group': Fore.YELLOW,
        'network_acl': Fore.MAGENTA,
        'vpc': Fore.CYAN
    }

    CHANGE_TYPE_COLORS = {
        'configuration': Fore.BLUE,
        'code': Fore.GREEN,
        'permission': Fore.YELLOW,
        'network': Fore.MAGENTA,
        'critical': Fore.RED
    }

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

    def _analyze_security_group_changes(self, event: Dict) -> Dict:
        """
        Analyze security group specific changes
        """
        changes = {}
        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            if 'UpdateSecurityGroupRuleDescriptionsIngress' in event['EventName']:
                changes['rules'] = "Inbound rules descriptions updated"
            elif 'UpdateSecurityGroupRuleDescriptionsEgress' in event['EventName']:
                changes['rules'] = "Outbound rules descriptions updated"
            elif 'AuthorizeSecurityGroupIngress' in event['EventName']:
                rules = request_params.get('ipPermissions', [])
                changes['rules'] = f"Added {len(rules)} new inbound rules"
            elif 'AuthorizeSecurityGroupEgress' in event['EventName']:
                rules = request_params.get('ipPermissions', [])
                changes['rules'] = f"Added {len(rules)} new outbound rules"
            elif 'RevokeSecurityGroupIngress' in event['EventName']:
                rules = request_params.get('ipPermissions', [])
                changes['rules'] = f"Removed {len(rules)} inbound rules"
            elif 'RevokeSecurityGroupEgress' in event['EventName']:
                rules = request_params.get('ipPermissions', [])
                changes['rules'] = f"Removed {len(rules)} outbound rules"

        except json.JSONDecodeError:
            logger.warning("Could not parse CloudTrail event JSON")

        return changes

    def _analyze_subnet_changes(self, event: Dict) -> Dict:
        """
        Analyze subnet specific changes
        """
        changes = {}
        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            if 'ModifySubnetAttribute' in event['EventName']:
                if 'mapPublicIpOnLaunch' in request_params:
                    value = request_params['mapPublicIpOnLaunch'].get('value', 'unknown')
                    changes['attribute'] = f"Auto-assign public IP set to: {value}"

            elif 'CreateTags' in event['EventName']:
                changes['tags'] = "Tags modified"

            elif 'CreateRoute' in event['EventName'] or 'DeleteRoute' in event['EventName']:
                changes['routing'] = "Route table modified"

        except json.JSONDecodeError:
            logger.warning("Could not parse CloudTrail event JSON")

        return changes

    def _get_related_resources(self) -> List[Dict]:
        """
        Get related resources and their changes
        """
        related_resources = []
        try:
            logger.info(f"Getting related resources for {self.resource_identifier}")

            # Get Lambda configuration
            lambda_client = self.session.client('lambda')
            logger.info("Getting Lambda configuration...")

            function = lambda_client.get_function(FunctionName=self.resource_identifier)
            vpc_config = function['Configuration'].get('VpcConfig', {})

            logger.info(f"VPC Config found: {vpc_config}")

            if vpc_config:
                # Get Security Groups changes
                ec2_client = self.session.client('ec2')
                if vpc_config.get('SecurityGroupIds'):
                    logger.info(f"Found Security Groups: {vpc_config['SecurityGroupIds']}")
                    for sg_id in vpc_config['SecurityGroupIds']:
                        try:
                            logger.info(f"Analyzing Security Group: {sg_id}")
                            # Get SG details
                            sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                            logger.info(f"Security Group details: {sg['GroupName']}")

                            sg_events = self._get_resource_events(sg_id, 'security_group')
                            logger.info(f"Found {len(sg_events)} events for SG {sg_id}")

                            # Analyze SG changes
                            sg_changes = []
                            for event in sg_events:
                                if changes := self._analyze_security_group_changes(event):
                                    sg_changes.append({
                                        'timestamp': event['EventTime'],
                                        'user': self._get_user_info(event),
                                        'event_type': event['EventName'],
                                        'changes': changes
                                    })

                            logger.info(f"Found {len(sg_changes)} changes for SG {sg_id}")

                            if sg_changes:
                                related_resources.append({
                                    'type': 'security_group',
                                    'identifier': f"{sg_id} ({sg.get('GroupName', 'Unknown')})",
                                    'changes': sg_changes
                                })
                        except ClientError as e:
                            logger.error(f"Error analyzing security group {sg_id}: {e}")
                else:
                    logger.info("No Security Groups found in VPC config")

                # Get Subnet changes
                if vpc_config.get('SubnetIds'):
                    logger.info(f"Found Subnets: {vpc_config['SubnetIds']}")
                    for subnet_id in vpc_config['SubnetIds']:
                        try:
                            logger.info(f"Analyzing Subnet: {subnet_id}")
                            # Get subnet details
                            subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                            logger.info(f"Subnet details: {subnet.get('CidrBlock')}")

                            subnet_events = self._get_resource_events(subnet_id, 'subnet')
                            logger.info(f"Found {len(subnet_events)} events for Subnet {subnet_id}")

                            # Analyze subnet changes
                            subnet_changes = []
                            for event in subnet_events:
                                if changes := self._analyze_subnet_changes(event):
                                    subnet_changes.append({
                                        'timestamp': event['EventTime'],
                                        'user': self._get_user_info(event),
                                        'event_type': event['EventName'],
                                        'changes': changes
                                    })

                            logger.info(f"Found {len(subnet_changes)} changes for Subnet {subnet_id}")

                            if subnet_changes:
                                vpc_id = subnet.get('VpcId', 'Unknown')
                                cidr = subnet.get('CidrBlock', 'Unknown')
                                related_resources.append({
                                    'type': 'subnet',
                                    'identifier': f"{subnet_id} (CIDR: {cidr}, VPC: {vpc_id})",
                                    'changes': subnet_changes
                                })
                        except ClientError as e:
                            logger.error(f"Error analyzing subnet {subnet_id}: {e}")
                else:
                    logger.info("No Subnets found in VPC config")
            else:
                logger.info("Lambda function is not VPC-enabled")

            # Get IAM Role changes
            iam_role = function['Configuration'].get('Role')
            if iam_role:
                logger.info(f"Found IAM Role: {iam_role}")
                role_events = self._get_resource_events(iam_role.split('/')[-1], 'role')
                logger.info(f"Found {len(role_events)} events for Role {iam_role}")

                role_changes = self._analyze_changes(role_events)
                if role_changes:
                    related_resources.append({
                        'type': 'iam_role',
                        'identifier': iam_role,
                        'changes': role_changes
                    })
            else:
                logger.info("No IAM Role found")

        except ClientError as e:
            logger.error(f"Error getting related resources: {e}")

        logger.info(f"Total related resources with changes: {len(related_resources)}")
        return related_resources

    def _get_resource_events(self, resource_id: str, resource_type: str) -> List[Dict]:
        """
        Get CloudTrail events for a specific resource
        """
        try:
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')

            for page in paginator.paginate(
                    StartTime=self.start_time,
                    LookupAttributes=[{
                        'AttributeKey': 'ResourceName',
                        'AttributeValue': resource_id
                    }]
            ):
                for event in page.get('Events', []):
                    if self._is_relevant_event(event):
                        events.append(event)

            return events
        except ClientError as e:
            logger.error(f"Error getting events for {resource_type} {resource_id}: {e}")
            return []

    def analyze(self) -> Dict:
        """
        Main analysis method to detect and report changes
        """
        resource_arn = self._get_resource_arn()
        resource_type = self._get_resource_type()

        # Get main resource changes
        events = self._get_cloudtrail_events()
        changes = self._analyze_changes(events)

        # Get related resource changes
        related_resources = []
        if self.include_related:
            related_resources = self._get_related_resources()

        # Initialize the report
        report = {
            'resource_identifier': self.resource_identifier,
            'resource_type': resource_type,
            'analysis_period_days': self.days,
            'analysis_time': datetime.utcnow().isoformat(),
            'changes': changes,
            'related_resources': related_resources
        }

        return report


def print_changes(changes: List[Dict], resource_type: str, indent: str = "") -> None:
    """
    Print changes with color formatting
    """
    for change in changes:
        # Format timestamp
        timestamp = datetime.strptime(str(change['timestamp']), "%Y-%m-%d %H:%M:%S%z")
        formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        print(f"\n{indent}{Fore.WHITE}{formatted_time}")
        print(f"{indent}Action: {Fore.CYAN}{change['event_type']}{Style.RESET_ALL}")
        print(f"{indent}By: {Fore.YELLOW}{change['user']}{Style.RESET_ALL}")

        if change.get('changes'):
            print(f"{indent}Changes detected:")
            for change_type, change_desc in change['changes'].items():
                color = AWSResourceMonitor.CHANGE_TYPE_COLORS.get(change_type, Fore.WHITE)
                print(f"{indent}  - {color}{change_type}: {change_desc}{Style.RESET_ALL}")


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

        # Print header
        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Analysis Report for {Fore.GREEN}{args.resource}{Style.RESET_ALL}")
        print(f"Time period: Last {args.d} days")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")

        # Print main resource changes
        print(f"{Fore.GREEN}Direct Resource Changes:{Style.RESET_ALL}")
        if not report['changes']:
            print(f"\n{Fore.YELLOW}No significant changes detected.{Style.RESET_ALL}")
        else:
            print_changes(report['changes'], report['resource_type'])

        # Print related resource changes
        if args.include_related and report['related_resources']:
            print(f"\n{Fore.GREEN}Related Resource Changes:{Style.RESET_ALL}")
            for related in report['related_resources']:
                color = AWSResourceMonitor.RESOURCE_TYPE_COLORS.get(related['type'], Fore.WHITE)
                print(f"\n{color}{related['type'].upper()}: {related['identifier']}{Style.RESET_ALL}")
                if related['changes']:
                    print_changes(related['changes'], related['type'], indent="  ")
                else:
                    print(f"  {Fore.YELLOW}No significant changes detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    except Exception as e:
        logger.error(f"{Fore.RED}Error analyzing resource: {e}{Style.RESET_ALL}")
        raise


if __name__ == "__main__":
    main()