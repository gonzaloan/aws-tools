# aws-tools

Some utilities.

## Lambda Monitoring Usage

```bash
$ python lambda-monitoring.py --resource {name_of_the_lambda_function} --d {days_for_range_of_changes} --include-related
```

## Memcached viewer

```bash
## List all keys
python script.py --endpoint your-endpoint.cache.amazonaws.com --list-keys

## get Specific Key Value

python script.py --endpoint your-endpoint.cache.amazonaws.com --list-keys

## View stats

python script.py --endpoint your-endpoint.cache.amazonaws.com --stats


## Use different port

python script.py --endpoint your-endpoint.cache.amazonaws.com --port 11212 --list-keys


```