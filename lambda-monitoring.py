#!/usr/bin/env python3
import json
import sys
import boto3
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from botocore.exceptions import ClientError
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configure logging only once
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AWSResourceMonitor:
    RESOURCE_TYPE_COLORS = {
        'lambda': Fore.BLUE,
        'subnet': Fore.GREEN,
        'security_group': Fore.YELLOW,
        'network_acl': Fore.MAGENTA,
        'vpc': Fore.CYAN,
        'iam_role': Fore.WHITE
    }

    CHANGE_TYPE_COLORS = {
        'configuration': Fore.BLUE,
        'code': Fore.GREEN,
        'permission': Fore.YELLOW,
        'network': Fore.MAGENTA,
        'critical': Fore.RED,
        'policy': Fore.CYAN
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
        self.lambda_client = self.session.client('lambda')
        self.ec2_client = self.session.client('ec2')
        self.iam_client = self.session.client('iam')
        self.start_time = datetime.utcnow() - timedelta(days=days)

    def _get_resource_arn(self) -> str:
        """Convert resource identifier to ARN if needed"""
        if self.resource_identifier.startswith('arn:'):
            return self.resource_identifier

        # Construct ARN for Lambda function
        if ':lambda:' in self.resource_identifier or self._get_resource_type() == 'lambda':
            region = self.session.region_name
            account = self.session.client('sts').get_caller_identity()['Account']
            return f'arn:aws:lambda:{region}:{account}:function:{self.resource_identifier}'

        return self.resource_identifier

    def _get_resource_type(self) -> str:
        """Determine the AWS resource type from the identifier"""
        resource_types = {
            'lambda': lambda x: 'function' in x.lower() or ':lambda:' in x,
            'subnet': lambda x: x.startswith('subnet-'),
            'security_group': lambda x: x.startswith('sg-'),
            'vpc': lambda x: x.startswith('vpc-'),
            'iam_role': lambda x: 'role' in x.lower() or ':iam:' in x
        }

        for resource_type, check_func in resource_types.items():
            if check_func(self.resource_identifier):
                return resource_type

        return 'unknown'

    def _is_relevant_event(self, event: Dict) -> bool:
        """Filter out non-relevant events"""
        ignored_events = {
            'AssumeRole', 'ConsoleLogin', 'BatchGetTraces',
            'StartQueryExecution', 'GetQueryExecution', 'GetQueryResults',
            'ListTags', 'GetFunction', 'DescribeFunction', 'GetPolicy',
            'GetRolePolicy', 'DescribeSecurityGroups', 'DescribeSubnets'
        }

        if event['EventName'] in ignored_events:
            return False

        if event['EventName'].startswith(('Get', 'List', 'Describe', 'Head')):
            return False

        return True

    def _get_user_info(self, event: Dict) -> str:
        """Extract meaningful user information from the event"""
        user_identity = event.get('UserIdentity', {})

        if 'sessionContext' in user_identity:
            session_context = user_identity['sessionContext']
            if 'sessionIssuer' in session_context:
                return f"{session_context['sessionIssuer'].get('userName', 'Unknown')} via {user_identity.get('type', 'Unknown')}"

        identity_types = {
            'IAMUser': lambda x: x.get('userName', 'Unknown IAM User'),
            'AssumedRole': lambda x: f"Role: {x.get('arn', '').split('/')[-1]}",
            'Root': lambda x: 'AWS Root User'
        }

        return identity_types.get(user_identity.get('type'), lambda x: x.get('userName', 'Unknown'))(user_identity)

    def _get_cloudtrail_events(self, resource_id: Optional[str] = None) -> List[Dict]:
        """Retrieve CloudTrail events for the resource"""
        try:
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')

            lookup_attributes = [{
                'AttributeKey': 'ResourceName',
                'AttributeValue': resource_id or self.resource_identifier
            }]

            for page in paginator.paginate(StartTime=self.start_time, LookupAttributes=lookup_attributes):
                events.extend([event for event in page.get('Events', []) if self._is_relevant_event(event)])

            return events

        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail events: {e}")
            return []

    def _analyze_changes(self, events: List[Dict], resource_type: str = None) -> List[Dict]:
        """Analyze the changes from CloudTrail events"""
        changes = []

        for event in events:
            try:
                user = self._get_user_info(event)
                event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
                request_params = event_detail.get('requestParameters', {})
                response_elements = event_detail.get('responseElements', {})

                change = {
                    'timestamp': event['EventTime'],
                    'user': user,
                    'event_type': event['EventName'],
                    'event_source': event['EventSource'],
                    'changes': {}
                }

                # Get changes based on resource type
                if resource_type == 'security_group':
                    change['changes'] = self._analyze_security_group_changes(event)
                elif resource_type == 'subnet':
                    change['changes'] = self._analyze_subnet_changes(event)
                elif resource_type == 'iam_role':
                    change['changes'] = self._analyze_iam_changes(event)
                else:
                    change['changes'] = self._extract_meaningful_changes(
                        event['EventName'],
                        request_params,
                        response_elements
                    )

                if change['changes']:
                    changes.append(change)

            except (KeyError, json.JSONDecodeError) as e:
                logger.warning(f"Error processing event: {e}")
                continue

        return changes

    def _extract_meaningful_changes(self, event_name: str, request_params: Dict, response_elements: Dict) -> Dict:
        """Extract meaningful changes based on the event type"""
        changes = {}

        if 'UpdateFunctionConfiguration' in event_name:
            for param in ['memorySize', 'timeout']:
                if param in request_params:
                    changes[param] = f"Changed to {request_params[param]}"
            if 'environment' in request_params:
                changes['environment'] = "Environment variables modified"

        elif 'UpdateFunctionCode' in event_name:
            changes['code'] = "Function code updated"
            if 'revisionId' in response_elements:
                changes['revision'] = f"New revision: {response_elements['revisionId']}"

        elif 'AddPermission' in event_name or 'RemovePermission' in event_name:
            changes['permissions'] = "Function permissions modified"

        return changes

    def _analyze_security_group_changes(self, event: Dict) -> Dict:
        """Analyze security group specific changes"""
        event_handlers = {
            'UpdateSecurityGroupRuleDescriptionsIngress': ('rules', "Inbound rules descriptions updated"),
            'UpdateSecurityGroupRuleDescriptionsEgress': ('rules', "Outbound rules descriptions updated"),
            'AuthorizeSecurityGroupIngress': (
            'rules', lambda p: f"Added {len(p.get('ipPermissions', []))} new inbound rules"),
            'AuthorizeSecurityGroupEgress': (
            'rules', lambda p: f"Added {len(p.get('ipPermissions', []))} new outbound rules"),
            'RevokeSecurityGroupIngress': (
            'rules', lambda p: f"Removed {len(p.get('ipPermissions', []))} inbound rules"),
            'RevokeSecurityGroupEgress': (
            'rules', lambda p: f"Removed {len(p.get('ipPermissions', []))} outbound rules")
        }

        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            for event_type, (change_key, change_value) in event_handlers.items():
                if event_type in event['EventName']:
                    if callable(change_value):
                        return {change_key: change_value(request_params)}
                    return {change_key: change_value}

        except json.JSONDecodeError:
            logger.warning("Could not parse CloudTrail event JSON")

        return {}

    def _analyze_subnet_changes(self, event: Dict) -> Dict:
        """Analyze subnet specific changes"""
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

    def _analyze_iam_changes(self, event: Dict) -> Dict:
        """Analyze IAM specific changes"""
        event_handlers = {
            'PutRolePolicy': lambda p: f"Added/Updated inline policy: {p.get('policyName', 'unknown')}",
            'DeleteRolePolicy': lambda p: f"Removed inline policy: {p.get('policyName', 'unknown')}",
            'AttachRolePolicy': lambda p: f"Attached managed policy: {p.get('policyArn', 'unknown')}",
            'DetachRolePolicy': lambda p: f"Detached managed policy: {p.get('policyArn', 'unknown')}"
        }

        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            for event_type, handler in event_handlers.items():
                if event_type in event['EventName']:
                    return {'policy': handler(request_params)}

        except json.JSONDecodeError:
            logger.warning("Could not parse CloudTrail event JSON")

        return {}

    def _get_related_resources(self) -> List[Dict]:
        """Get related resources and their changes"""
        try:
            function = self.lambda_client.get_function(FunctionName=self.resource_identifier)
            vpc_config = function['Configuration'].get('VpcConfig', {})
            related_resources = []

            if vpc_config:
                # Analyze Security Groups
                for sg_id in vpc_config.get('SecurityGroupIds', []):
                    try:
                        sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                        sg_events = self._get_cloudtrail_events(sg_id)
                        sg_changes = self._analyze_changes(sg_events, 'security_group')

                        related_resources.append({
                            'type': 'security_group',
                            'identifier': sg_id,
                            'name': sg.get('GroupName', 'Unknown'),
                            'description': sg.get('Description', 'No description'),
                            'vpc_id': sg.get('VpcId', 'Unknown'),
                            'changes': sg_changes
                        })
                    except ClientError as e:
                        logger.error(f"Error analyzing security group {sg_id}: {e}")

                # Analyze Subnets
                for subnet_id in vpc_config.get('SubnetIds', []):
                    try:
                        subnet = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
                        subnet_events = self._get_cloudtrail_events(subnet_id)
                        subnet_changes = self._analyze_changes(subnet_events, 'subnet')

                        related_resources.append({
                            'type': 'subnet',
                            'identifier': subnet_id,
                            'cidr': subnet.get('CidrBlock', 'Unknown'),
                            'vpc_id': subnet.get('VpcId', 'Unknown'),
                            'az': subnet.get('AvailabilityZone', 'Unknown'),
                            'changes': subnet_changes
                        })
                    except ClientError as e:
                        logger.error(f"Error analyzing subnet {subnet_id}: {e}")

            # Analyze IAM Role
            iam_role = function['Configuration'].get('Role')
            if iam_role:
                role_name = iam_role.split('/')[-1]
                role_events = self._get_cloudtrail_events(role_name)
                role_changes = self._analyze_changes(role_events, 'iam_role')

                related_resources.append({
                    'type': 'iam_role',
                    'identifier': iam_role,
                    'name': role_name,
                    'changes': role_changes
                })

            return related_resources

        except ClientError as e:
            logger.error(f"Error getting related resources: {e}")
            return []

    def analyze(self) -> Dict:
        """
        Main analysis method to detect and report changes
        """
        try:
            # Get resource type and basic info
            resource_type = self._get_resource_type()
            resource_arn = self._get_resource_arn()

            # Initialize the basic report structure
            report = {
                'resource_identifier': self.resource_identifier,
                'resource_type': resource_type,
                'analysis_period_days': self.days,
                'analysis_time': datetime.utcnow().isoformat(),
                'changes': [],
                'related_resources': []
            }

            # Get main resource changes
            events = self._get_cloudtrail_events()
            report['changes'] = self._analyze_changes(events, resource_type)

            # Handle Lambda-specific details
            if resource_type == 'lambda':
                try:
                    function = self.lambda_client.get_function(FunctionName=self.resource_identifier)
                    config = function['Configuration']

                    report['lambda_details'] = {
                        'runtime': config.get('Runtime', 'Unknown'),
                        'memory': config.get('MemorySize', 'Unknown'),
                        'timeout': config.get('Timeout', 'Unknown'),
                        'handler': config.get('Handler', 'Unknown'),
                        'last_modified': config.get('LastModified', 'Unknown')
                    }

                    # Get related resources if requested
                    if self.include_related:
                        report['related_resources'] = self._get_related_resources()
                except ClientError as e:
                    logger.error(f"Error getting Lambda details: {e}")
                    report['lambda_details'] = {
                        'error': f"Could not retrieve Lambda details: {str(e)}"
                    }

            return report

        except Exception as e:
            logger.error(f"Error analyzing resource: {e}")
            raise


def format_resource_header(text: str) -> str:
    """Format section headers with consistent styling"""
    return f"{Fore.CYAN}{'=' * 80}\n{text}\n{'=' * 80}{Style.RESET_ALL}"


def print_lambda_details(details: Dict):
    """Print Lambda function configuration details"""
    print(f"\n{Fore.YELLOW}Lambda Configuration:{Style.RESET_ALL}")
    print(f"  Runtime: {details['runtime']}")
    print(f"  Memory: {details['memory']} MB")
    print(f"  Timeout: {details['timeout']} seconds")
    print(f"  Handler: {details['handler']}")
    print(f"  Last Modified: {details['last_modified']}")


def print_changes(changes: List[Dict], resource_type: str, indent: str = "") -> None:
    """Print changes with color formatting"""
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


def print_related_resources(resources: List[Dict]):
    """Print related resources information"""
    if not resources:
        print(f"\n{Fore.YELLOW}No related resources found{Style.RESET_ALL}")
        return

    # Group resources by type
    resource_groups = {
        'security_group': [],
        'subnet': [],
        'iam_role': []
    }

    for resource in resources:
        if resource['type'] in resource_groups:
            resource_groups[resource['type']].append(resource)

    # Print Security Groups
    if resource_groups['security_group']:
        print(f"\n{Fore.YELLOW}Security Groups:{Style.RESET_ALL}")
        for sg in resource_groups['security_group']:
            print(f"\n  {Fore.WHITE}• {sg['identifier']}{Style.RESET_ALL}")
            print(f"    Name: {sg['name']}")
            print(f"    Description: {sg['description']}")
            print(f"    VPC: {sg['vpc_id']}")

            if sg['changes']:
                print(f"\n    Changes detected:")
                for change in sg['changes']:
                    print(f"\n    [{change['timestamp']}]")
                    print(f"    Modified by: {change['user']}")
                    for change_type, desc in change['changes'].items():
                        print(f"      - {change_type}: {desc}")

    # Print Subnets
    if resource_groups['subnet']:
        print(f"\n{Fore.YELLOW}Subnets:{Style.RESET_ALL}")
        for subnet in resource_groups['subnet']:
            print(f"\n  {Fore.WHITE}• {subnet['identifier']}{Style.RESET_ALL}")
            print(f"    CIDR: {subnet['cidr']}")
            print(f"    VPC: {subnet['vpc_id']}")
            print(f"    Availability Zone: {subnet['az']}")

            if subnet['changes']:
                print(f"\n    Changes detected:")
                for change in subnet['changes']:
                    print(f"\n    [{change['timestamp']}]")
                    print(f"    Modified by: {change['user']}")
                    for change_type, desc in change['changes'].items():
                        print(f"      - {change_type}: {desc}")

    # Print IAM Roles
    if resource_groups['iam_role']:
        print(f"\n{Fore.YELLOW}IAM Role:{Style.RESET_ALL}")
        for role in resource_groups['iam_role']:
            print(f"\n  {Fore.WHITE}• {role['identifier']}{Style.RESET_ALL}")
            if role['changes']:
                print(f"\n    Changes detected:")
                for change in role['changes']:
                    print(f"\n    [{change['timestamp']}]")
                    print(f"    Modified by: {change['user']}")
                    for change_type, desc in change['changes'].items():
                        print(f"      - {change_type}: {desc}")


def main():
    """Main function to run the AWS Resource Monitor"""
    parser = argparse.ArgumentParser(description='Monitor AWS resource changes')
    parser.add_argument('--resource', required=True, help='Resource ARN or name')
    parser.add_argument('--d', type=int, default=7, help='Number of days to look back')
    parser.add_argument('--include-related', action='store_true',
                        help='Include related resource changes')

    args = parser.parse_args()

    try:
        # Initialize the monitor
        monitor = AWSResourceMonitor(
            resource_identifier=args.resource,
            days=args.d,
            include_related=args.include_related
        )

        # Get the analysis report
        report = monitor.analyze()

        # Print main header
        print(format_resource_header(f"Analysis Report for {args.resource}\nTime period: Last {args.d} days"))

        # Print resource-specific details
        if report['resource_type'] == 'lambda' and 'lambda_details' in report:
            print_lambda_details(report['lambda_details'])

        # Print direct changes
        print(f"\n{Fore.GREEN}Direct Resource Changes:{Style.RESET_ALL}")
        if not report['changes']:
            print(f"\n{Fore.YELLOW}No changes detected in the {report['resource_type']}{Style.RESET_ALL}")
        else:
            print_changes(report['changes'], report['resource_type'])

        # Print related resources if included and available
        if args.include_related and report.get('related_resources'):
            print(f"\n{Fore.GREEN}Related Resources:{Style.RESET_ALL}")
            print_related_resources(report['related_resources'])

        print(f"\n{format_resource_header('End of Report')}")

    except Exception as e:
        logger.error(f"{Fore.RED}Error analyzing resource: {e}{Style.RESET_ALL}")
        logger.debug("Exception details:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()