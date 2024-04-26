#!/usr/bin/env python3

from serles import create_app

from .configloader import get_config

if __name__ == "__main__":
    config, _ = get_config()
    create_app().run(host=config["host"], port=config["port"], ssl_context="adhoc")
