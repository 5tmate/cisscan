import argparse
import sys

from botocore.exceptions import NoCredentialsError, ProfileNotFound

import report as reporting
from adapters import terraformer
from adapters.document import make_document, write_document
from scanner import aws_api


def run(profile, regions, output, account=None, terraformer_dumps=None):
    if terraformer_dumps:
        document = terraformer.build_document(terraformer_dumps, account_id=account)
    else:
        try:
            resources, declared = aws_api.collect(profile, regions)
        except (NoCredentialsError, ProfileNotFound) as error:
            print(
                f"cisscan: no usable AWS credentials ({error}); pass --profile or set AWS_PROFILE",
                file=sys.stderr,
            )
            return 2
        document = make_document(resources, declared, account_id=account)
    path = write_document(document, output)
    code, result = reporting.run(path)
    if result:
        reporting.render(result, document["meta"])
    return code


def main():
    parser = argparse.ArgumentParser(
        description="Scan the AWS account and evaluate CIS AWS Foundations Benchmark v5.0.0 in one run"
    )
    parser.add_argument("--profile", help="AWS profile; default: the standard credential chain")
    parser.add_argument("--regions", help="comma separated, default: all enabled regions")
    parser.add_argument("--account")
    parser.add_argument("-o", "--output", default="out/resources.json")
    parser.add_argument(
        "--from-terraformer",
        nargs="+",
        metavar="DUMP_DIR",
        help="evaluate an existing terraformer dump instead of scanning",
    )
    arguments = parser.parse_args()
    regions = arguments.regions.split(",") if arguments.regions else None
    return run(
        profile=arguments.profile,
        regions=regions,
        output=arguments.output,
        account=arguments.account,
        terraformer_dumps=arguments.from_terraformer,
    )


if __name__ == "__main__":
    sys.exit(main())
