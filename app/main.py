import argparse

from .dns import Forwarder


def main():
    parser = argparse.ArgumentParser(description="DNS Forwarder")
    parser.add_argument("--resolver", help="Upstream DNS resolver (ip:port)", required=True)
    args = parser.parse_args()
    resolver_ip, resolver_port = args.resolver.split(":")
    resolver = (resolver_ip, int(resolver_port))

    forwarder = Forwarder(resolver)
    forwarder.start()


if __name__ == "__main__":
    main()
