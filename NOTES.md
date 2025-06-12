# NOTES

## Terminology

### KEY

Unique identifier associated to a specific value.

`{key: value}`

### HKEY

Unique identifier associated to a hashmap:

`{hkey: {field: value, ..., field: value }}`

A **HKEY** is made of an **index** and a *unique id*: `INDEX:ID`.

### Field

A **field** is a **key** inside a hashmap.

### Index

An **index** is a unique identifier that holds similar hashmaps, i.e.:

```
  <index>
  MYHASH
  |   <index> <ID>    
  |___ MYHASH:1
  |___ MYHASH:2
  |___ MYHASH:3
```

### Reference

*HKEY* used as a *value* in a *field*

