#### Casbin Pebble Adapter (Experimental)

A simple Casbin Pebble Adapter (see https://casbin.org/docs/en/adapters).
This flavour supports the **auto-save** functionality.

Right now it supports the autosave functionality, and I've worked in some restricted filtered adapter functionality - difficult with a simple k/v store.

Individual policy lines get saved into the specified Pebble DB which is keyed using a `::` delimited value of the
role. The value content is a JSON representation of the policy rule.
