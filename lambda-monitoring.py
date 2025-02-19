#!/usr/bin/env python3
import json
import boto3
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional
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
        """Enhanced filter for relevant events"""
        # Events that should always be ignored
        ignored_events = {
            'AssumeRole', 'ConsoleLogin', 'BatchGetTraces',
            'StartQueryExecution', 'GetQueryExecution', 'GetQueryResults',
            'ListTags', 'GetFunction', 'DescribeFunction', 'GetPolicy',
            'GetRolePolicy', 'DescribeSecurityGroups', 'DescribeSubnets'
        }

        if event['EventName'] in ignored_events:
            return False

        # For security groups, include all authorization events
        if any(keyword in event['EventName'] for keyword in [
            'AuthorizeSecurityGroup', 'RevokeSecurityGroup',
            'UpdateSecurityGroupRule', 'ModifySecurityGroup'
        ]):
            return True

        # For subnets, include all modification events
        if any(keyword in event['EventName'] for keyword in [
            'ModifySubnet', 'CreateRoute', 'DeleteRoute',
            'AssociateRouteTable', 'DisassociateRouteTable'
        ]):
            return True

        # For standard read operations, ignore
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
        """Retrieve CloudTrail events for the resource with improved lookup"""
        try:
            events = []
            paginator = self.cloudtrail.get_paginator('lookup_events')

            # Use the appropriate resource identifier
            identifier = resource_id or self.resource_identifier

            # CloudTrail only accepts certain attribute keys
            lookup_attributes = []

            # Only add ResourceName if it's a valid identifier
            if not identifier.startswith(('arn:', 'sg-', 'subnet-', 'vpc-')):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': identifier
                })

            # Add ResourceType for specific resource types
            if identifier.startswith('sg-'):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceType',
                    'AttributeValue': 'AWS::EC2::SecurityGroup'
                })
            elif identifier.startswith('subnet-'):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceType',
                    'AttributeValue': 'AWS::EC2::Subnet'
                })
            elif identifier.startswith('vpc-'):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceType',
                    'AttributeValue': 'AWS::EC2::VPC'
                })

            # If it's an ARN, use it directly
            if identifier.startswith('arn:'):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': identifier
                })

            # If we have a valid ID (sg-, subnet-, etc), use it
            elif any(identifier.startswith(prefix) for prefix in ['sg-', 'subnet-', 'vpc-']):
                lookup_attributes.append({
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': identifier
                })

            # For each valid lookup attribute
            for lookup_attr in lookup_attributes:
                try:
                    logger.info(f"Looking up events with attribute: {lookup_attr}")
                    for page in paginator.paginate(
                            StartTime=self.start_time,
                            LookupAttributes=[lookup_attr]
                    ):
                        filtered_events = [
                            event for event in page.get('Events', [])
                            if self._is_relevant_event(event)
                        ]
                        events.extend(filtered_events)
                        logger.info(f"Found {len(filtered_events)} relevant events for {lookup_attr}")
                except ClientError as e:
                    logger.warning(f"Error with lookup attribute {lookup_attr}: {e}")
                    continue

            # Remove duplicate events
            unique_events = {event['EventId']: event for event in events}.values()
            return sorted(unique_events, key=lambda x: x['EventTime'])

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

    def _format_ip_permissions(self, permissions: List[Dict]) -> str:
        """Format IP permissions for better readability"""
        formatted = []
        for perm in permissions:
            protocol = perm.get('ipProtocol', '-1')
            from_port = perm.get('fromPort', 'All')
            to_port = perm.get('toPort', 'All')

            ranges = []
            for ip_range in perm.get('ipRanges', []):
                cidr = ip_range.get('cidrIp', '')
                desc = ip_range.get('description', '')
                ranges.append(f"{cidr} ({desc})" if desc else cidr)

            formatted.append(
                f"Protocol: {protocol}, Ports: {from_port}-{to_port}, "
                f"IPs: {', '.join(ranges) or 'None'}"
            )

        return '; '.join(formatted)
    def _analyze_security_group_changes(self, event: Dict) -> Dict:
        """Enhanced analysis of security group specific changes"""
        changes = {}

        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            event_handlers = {
                'AuthorizeSecurityGroupIngress': (
                    'rules',
                    lambda p: f"Added {len(p.get('ipPermissions', []))} new inbound rules: " +
                              self._format_ip_permissions(p.get('ipPermissions', []))
                ),
                'AuthorizeSecurityGroupEgress': (
                    'rules',
                    lambda p: f"Added {len(p.get('ipPermissions', []))} new outbound rules: " +
                              self._format_ip_permissions(p.get('ipPermissions', []))
                ),
                'RevokeSecurityGroupIngress': (
                    'rules',
                    lambda p: f"Removed {len(p.get('ipPermissions', []))} inbound rules: " +
                              self._format_ip_permissions(p.get('ipPermissions', []))
                ),
                'RevokeSecurityGroupEgress': (
                    'rules',
                    lambda p: f"Removed {len(p.get('ipPermissions', []))} outbound rules: " +
                              self._format_ip_permissions(p.get('ipPermissions', []))
                )
            }

            for event_type, (change_key, change_handler) in event_handlers.items():
                if event_type in event['EventName']:
                    if callable(change_handler):
                        changes[change_key] = change_handler(request_params)
                    else:
                        changes[change_key] = change_handler

        except json.JSONDecodeError:
            logger.warning("Could not parse CloudTrail event JSON")

        return changes

    def _analyze_subnet_changes(self, event: Dict) -> Dict:
        """Enhanced analysis of subnet specific changes"""
        changes = {}

        try:
            event_detail = json.loads(event.get('CloudTrailEvent', '{}'))
            request_params = event_detail.get('requestParameters', {})

            if 'ModifySubnetAttribute' in event['EventName']:
                for attr, value in request_params.items():
                    if attr != 'subnetId':
                        changes['attribute'] = f"Modified {attr}: {value}"

            elif 'CreateRoute' in event['EventName']:
                dest_cidr = request_params.get('destinationCidrBlock', 'unknown')
                target = next((v for k, v in request_params.items() if 'target' in k.lower()), 'unknown')
                changes['routing'] = f"Added route to {dest_cidr} via {target}"

            elif 'DeleteRoute' in event['EventName']:
                dest_cidr = request_params.get('destinationCidrBlock', 'unknown')
                changes['routing'] = f"Removed route to {dest_cidr}"

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
        """Get related resources and their changes with enhanced details"""
        try:
            function = self.lambda_client.get_function(FunctionName=self.resource_identifier)
            vpc_config = function['Configuration'].get('VpcConfig', {})
            related_resources = []

            if vpc_config:
                # Get VPC details
                vpc_id = vpc_config.get('VpcId')
                if vpc_id:
                    try:
                        vpc = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
                        vpc_events = self._get_cloudtrail_events(vpc_id)
                        vpc_changes = self._analyze_changes(vpc_events, 'vpc')

                        related_resources.append({
                            'type': 'vpc',
                            'identifier': vpc_id,
                            'cidr': vpc.get('CidrBlock', 'Unknown'),
                            'state': vpc.get('State', 'Unknown'),
                            'is_default': vpc.get('IsDefault', False),
                            'changes': vpc_changes
                        })
                    except ClientError as e:
                        logger.warning(f"Error getting VPC details: {e}")

                # Get Security Group details with enhanced information
                for sg_id in vpc_config.get('SecurityGroupIds', []):
                    try:
                        sg = self.ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                        sg_events = self._get_cloudtrail_events(sg_id)
                        sg_changes = self._analyze_changes(sg_events, 'security_group')

                        # Get active rules count
                        inbound_rules = len(sg.get('IpPermissions', []))
                        outbound_rules = len(sg.get('IpPermissionsEgress', []))

                        related_resources.append({
                            'type': 'security_group',
                            'identifier': sg_id,
                            'name': sg.get('GroupName', 'Unknown'),
                            'description': sg.get('Description', 'No description'),
                            'vpc_id': sg.get('VpcId', 'Unknown'),
                            'inbound_rules': inbound_rules,
                            'outbound_rules': outbound_rules,
                            'changes': sg_changes
                        })
                    except ClientError as e:
                        logger.error(f"Error analyzing security group {sg_id}: {e}")

                # Get Subnet details with enhanced information
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
                            'state': subnet.get('State', 'Unknown'),
                            'available_ip_count': subnet.get('AvailableIpAddressCount', 0),
                            'public_ip_on_launch': subnet.get('MapPublicIpOnLaunch', False),
                            'changes': subnet_changes
                        })
                    except ClientError as e:
                        logger.error(f"Error analyzing subnet {subnet_id}: {e}")

            # Get IAM Role details with enhanced information
            role_arn = function['Configuration'].get('Role')
            if role_arn:
                try:
                    role_name = role_arn.split('/')[-1]
                    role = self.iam_client.get_role(RoleName=role_name)['Role']
                    role_events = self._get_cloudtrail_events(role_name)
                    role_changes = self._analyze_changes(role_events, 'iam_role')

                    # Get attached policies
                    attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)[
                        'AttachedPolicies']

                    related_resources.append({
                        'type': 'iam_role',
                        'identifier': role_arn,
                        'name': role_name,
                        'description': role.get('Description', 'No description'),
                        'created_date': role.get('CreateDate', 'Unknown'),
                        'last_used': role.get('RoleLastUsed', {}).get('LastUsedDate', 'Never'),
                        'attached_policies': [p['PolicyName'] for p in attached_policies],
                        'changes': role_changes
                    })
                except ClientError as e:
                    logger.error(f"Error analyzing IAM role: {e}")

            return related_resources

        except ClientError as e:
            logger.error(f"Error getting related resources: {e}")
            return []
    def analyze(self) -> Dict:
        """
        Main analysis method to detect and report changes
        """
        try:
            # Get Lambda function details
            function = self.lambda_client.get_function(FunctionName=self.resource_identifier)
            config = function['Configuration']

            # Get main resource changes
            events = self._get_cloudtrail_events()
            changes = self._analyze_changes(events)

            # Get Lambda configuration details
            lambda_details = {
                'runtime': config.get('Runtime', 'Unknown'),
                'memory': config.get('MemorySize', 'Unknown'),
                'timeout': config.get('Timeout', 'Unknown'),
                'handler': config.get('Handler', 'Unknown'),
                'last_modified': config.get('LastModified', 'Unknown')
            }

            # Get related resources if requested
            related_resources = []
            if self.include_related:
                related_resources = self._get_related_resources()

            # Create the complete report
            report = {
                'resource_identifier': self.resource_identifier,
                'resource_type': 'lambda',
                'lambda_details': lambda_details,
                'analysis_period_days': self.days,
                'analysis_time': datetime.utcnow().isoformat(),
                'changes': changes,
                'related_resources': related_resources
            }

            return report

        except ClientError as e:
            logger.error(f"Error analyzing Lambda function: {e}")
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
    """Print related resources information with enhanced details"""
    if not resources:
        print(f"\n{Fore.YELLOW}No related resources found{Style.RESET_ALL}")
        return

    for resource in resources:
        resource_type = resource['type']
        color = AWSResourceMonitor.RESOURCE_TYPE_COLORS.get(resource_type, Fore.WHITE)

        print(f"\n{color}=== {resource_type.upper()} Details ==={Style.RESET_ALL}")

        if resource_type == 'security_group':
            print(f"  Identifier: {resource['identifier']}")
            print(f"  Name: {resource['name']}")
            print(f"  Description: {resource['description']}")
            print(f"  VPC: {resource['vpc_id']}")
        elif resource_type == 'subnet':
            print(f"  Identifier: {resource['identifier']}")
            print(f"  CIDR Block: {resource['cidr']}")
            print(f"  VPC: {resource['vpc_id']}")
            print(f"  Availability Zone: {resource['az']}")
        elif resource_type == 'iam_role':
            print(f"  ARN: {resource['identifier']}")
            print(f"  Name: {resource['name']}")

        if resource.get('changes'):
            print(f"\n  {Fore.CYAN}Change History:{Style.RESET_ALL}")
            for change in resource['changes']:
                timestamp = datetime.strptime(str(change['timestamp']), "%Y-%m-%d %H:%M:%S%z")
                formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

                print(f"\n    {Fore.WHITE}[{formatted_time}]{Style.RESET_ALL}")
                print(f"    Modified by: {Fore.YELLOW}{change['user']}{Style.RESET_ALL}")
                print(f"    Event: {change['event_type']}")

                if change.get('changes'):
                    for change_type, desc in change['changes'].items():
                        color = AWSResourceMonitor.CHANGE_TYPE_COLORS.get(change_type, Fore.WHITE)
                        print(f"      {color}• {change_type}: {desc}{Style.RESET_ALL}")


def main():
    """Main function to run the AWS Resource Monitor"""
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

        # Print main header
        print(format_resource_header(f"Analysis Report for {args.resource}\nTime period: Last {args.d} days"))

        # Print Lambda details
        print_lambda_details(report['lambda_details'])

        # Print direct changes
        print(f"\n{Fore.GREEN}Direct Resource Changes:{Style.RESET_ALL}")
        if not report['changes']:
            print(f"\n{Fore.YELLOW}No changes detected in the Lambda function{Style.RESET_ALL}")
        else:
            print_changes(report['changes'], report['resource_type'])

        # Print related resources
        if args.include_related:
            print(f"\n{Fore.GREEN}Network Configuration and Related Resources:{Style.RESET_ALL}")
            print_related_resources(report['related_resources'])

        print(f"\n{format_resource_header('End of Report')}")

    except Exception as e:
        logger.error(f"{Fore.RED}Error analyzing resource: {e}{Style.RESET_ALL}")
        raise


if __name__ == "__main__":
    main()