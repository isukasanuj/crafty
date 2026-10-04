# crafty - a declarative + interactive engine for arbitrary TCP/UDP exchanges.
# Copyright (C) 2026 isukasanuj and the crafty authors.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. This program is distributed WITHOUT ANY WARRANTY. See the LICENSE file
# for the full GPLv3 text, and NOTICE for the authorized-use statement.
"""crafty - a declarative + interactive engine for arbitrary TCP/UDP protocol
exchanges, in either direction (client or listener).

See README.md for the design. This package is the v0 engine: the binary grammar
(expressions, bidirectional structs, framing, DSL), the transport layer, the
flow engine, sessions, and the two front doors (CLI + console).
"""

__version__ = "0.1.0"
