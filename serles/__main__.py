#!/usr/bin/env python3

import serles

if __name__ == "__main__":
    app = serles.create_app()
    # serles.config was initialized in serles.create_app(), and we can use it now
    app.run(host=serles.config["host"], port=serles.config["port"], ssl_context="adhoc")
