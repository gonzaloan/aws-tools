import argparse
from pymemcache.client.base import Client
import sys


def parse_arguments():
    parser = argparse.ArgumentParser(description='AWS Memcached Explorer Tool')
    parser.add_argument('--endpoint',
                        required=True,
                        help='ElastiCache endpoint (e.g., my-cache.xxxxx.cfg.region.cache.amazonaws.com)')
    parser.add_argument('--port',
                        type=int,
                        default=11211,
                        help='Memcached port (default: 11211)')
    parser.add_argument('--list-keys',
                        action='store_true',
                        help='List all keys and values')
    parser.add_argument('--get-key',
                        help='Get value for a specific key')
    parser.add_argument('--stats',
                        action='store_true',
                        help='Show server statistics')

    return parser.parse_args()


def connect_to_memcached(endpoint, port):
    try:
        client = Client((endpoint, port))
        return client
    except Exception as e:
        print(f"Error connecting to Memcached: {e}")
        sys.exit(1)


def list_keys(client):
    try:
        stats = client.stats('items')
        items = []

        for key in stats.keys():
            if b'items' in key:
                slab_id = key.split(b':')[1]
                items.extend(client.stats('cachedump', slab_id, 100))

        print("\nFound keys:")
        print("-" * 50)
        for key in items:
            value = client.get(key)
            print(f"Key: {key}")
            print(f"Value: {value}")
            print("-" * 50)

    except Exception as e:
        print(f"Error listing keys: {e}")


def get_key_value(client, key):
    try:
        value = client.get(key)
        if value is not None:
            print(f"\nKey: {key}")
            print(f"Value: {value}")
        else:
            print(f"\nKey '{key}' does not exist")
    except Exception as e:
        print(f"Error getting key value: {e}")


def show_stats(client):
    try:
        stats = client.stats()
        print("\nServer Statistics:")
        print("-" * 50)
        for key, value in stats.items():
            print(f"{key.decode()}: {value.decode() if isinstance(value, bytes) else value}")
    except Exception as e:
        print(f"Error getting statistics: {e}")


def main():
    args = parse_arguments()
    client = connect_to_memcached(args.endpoint, args.port)

    if args.list_keys:
        list_keys(client)
    elif args.get_key:
        get_key_value(client, args.get_key)
    elif args.stats:
        show_stats(client)
    else:
        print("Please specify an action: --list-keys, --get-key, or --stats")

    client.close()


if __name__ == "__main__":
    main()