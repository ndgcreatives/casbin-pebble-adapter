#### Casbin Pebble Adapter

A Casbin Pebble Adapter (see https://casbin.org/docs/adapters).

- **auto-save** functionality
- filtered adapter functionality

Individual policy lines get saved into the specified Pebble DB which is keyed using a `::` delimited value of the
role. The value content is a JSON representation of the policy rule.
