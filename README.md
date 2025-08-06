# QDB

**QDB** is a lightweight, schema-aware, graph-based **database engine** with a **compact custom query language** for fast and expressive data modeling and querying.

**QDB** is an experimental project under active development.

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

An **index** is a unique identifier that holds similar hashmaps, e.g.:

```
 [INDEX]
  MYHASH
  |   [INDEX] [ID]
  |___ MYHASH:0001
  |___ MYHASH:0002
  |___ MYHASH:0003
```

### Reference

**HKEY** used as a **value** in a **field**.

## Dynamic Schema

At its core, **QDB** is a *key/value* and *key/hashmap* store, with a twist: relations can be established between entities (indexes).

- When a field is assigned a **HKEY**, a **reference** is added (e.g., `song:1258` -> `album:133`). Thus a relation is created and becomes part of the schema.

- References are bidirectional and define the traversal path during queries.

Unlike traditional databases, **QDB** does not require a schema to be declared. The schema is automatically inferred and evolves as data is added.

## Basic Commands

| Command  | Syntax                   | Description                            |
| -------- | ------------------------ | -------------------------------------- |
| `SET`    | `SET <KEY> <VALUE>`      | Create/modify a key/value pair         |
| `MSET`   | `MSET <KEY> <VALUE> ...` | Create/modify multiple key/value pairs |
| `DEL`    | `DEL <KEY>`              | Delete a key and its associated value  |
| `MDEL`   | `MDEL <KEY1> <KEY2> ...` | Delete multiple keys                   |
| `KEYS`   | `KEYS`                   | List all existing keys                 |
| `COMMIT` | `COMMIT`                 | Save pending database changes          |

## Hashmap Commands

### W

Create/modify fields and values in a hashmap.

#### Syntax

`W <INDEX>|<HKEY> <FIELD1> <VALUE1> ... <FIELDN> <VALUEN>`

#### Examples

**Create `song:1258`:**

```
W song:1258 album album:133 artist artist:83 track 10 title "reniform puls"
```

**With `@autoid`:**

```
W @autoid(artist) name autechre
```

### Q

Query data.

#### Syntax

`Q <ROOT_INDEX>|<HKEY> [[EXPR1] ... [EXPRN]]`

#### Expression

| Form                 | Description                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `field`              | Display a field from the current index                                                                              |
| `field=value`        | Filter records where `field == value`                                                                               |
| `index:field`        | Follow relationship to another index and display field (use `*` wildcard to display all fields for the given index) |
| `index:field=value`  | Filter by value in related index                                                                                    |
| `index:++field`      | Sort results by this field (ascending)                                                                              |
| `index:--field`      | Sort results by this field (descending)                                                                             |
| `index:@[agg:field]` | Aggregation (e.g. `@[count:field]`)                                                                                 |

#### Virtual fields

These are *convenience* fields that can be used to display and/or filter data in queries.

| Virtual field | Description                              |
| ------------- | ---------------------------------------- |
| `$hkey`       | The full **HKEY**, e.g. `artist:83`      |
| `$id`         | The **ID** part of a **HKEY**, e.g. `83` |

### Condition operators

| Operator                         | Description           |
| -------------------------------- | --------------------- |
| `=`                              | Equal                 |
| `!=`                             | Not equal             |
| `<`                              | Less than             |
| `<=`                             | Less than or equal    |
| `>`                              | Greater than          |
| `>=`                             | Greater than or equal |
| `^`                              | Starts with           |
| `!^`                             | Does not start with   |
| `$`                              | Ends with             |
| `!$`                             | Does not end with     |
| `**`                             | Contains              |
| `(value1, value2, ..., valueN)`  | In                    |
| `!(value1, value2, ..., valueN)` | Not in                |

#### Aggregation functions

| Function | Description |
| -------- | ----------- |
| `avg`    | Average     |
| `count`  | Count       |
| `max`    | Maximum     |
| `min`    | Minimum     |
| `sum`    | Sum         |

> Note: the sorting prefix must be added before the aggregation function e.g. `Q artist:83 name album:date:title song:@[--count:*]`.

#### Examples

**Display all HKEY/fields for the given index:**

```
Q artist
```

**Simple field display:**

```
Q artist name
```

**Filtering:**

```
Q artist name=autechre
```

**Navigation:**

```
Q artist name album:++date:title
```

*→ For each artist show their name and their albums sorted by date.*

**Aggregation:**

```
Q artist name=kraftwerk album:++date:title song:@[count:*]
```

*→ For artist "kraftwerk", list their album sorted by date and the number of songs per album.*

#### SQL vs QDB

##### SQL:

```
SELECT artist.name, song.title FROM artist
JOIN album ON album.artist_id = artist.id
JOIN song ON song.album_id = album.id
WHERE artist.name IN ('autechre', 'the cure')
ORDER BY song.title ASC;
```

##### QDB:

```
Q artist name(autechre,"the cure") song:++title
```

- `artist name(...)`: filter artists by name
- `song:title`: follow reference to `song` and select its title
- `++`: sort ascending by title

### Other Hashmap Commands

| Command  | Syntax                                       | Description                                                     |
| -------- | -------------------------------------------- | --------------------------------------------------------------- |
| `QF`     | `QF <HKEY> <FIELD>`                          | Display the value of a specific field for a given **HKEY**      |
| `QQ`     | `QQ <INDEX> <EXPR>`                          | Store **HKEY**S matching the given expression                   |
| `HDEL`   | `HDEL <INDEX>\|<HKEY> [FIELD1] [FIELD2] ...` | Delete an index, a **HKEY** or fields in an index or a **HKEY** |
| `HLEN`   | `HLEN <INDEX>`                               | Display the number of **HKEY**S for a specific index            |
| `IDX`    | `IDX`                                        | Display existing indexes                                        |
| `IDXF`   | `IDXF <INDEX>`                               | Show fields for a specific index                                |
| `SCHEMA` | `SCHEMA`                                     | Show current database schema                                    |

## User Management Commands

| Command   | Syntax                                      | Description                    |
| --------- | ------------------------------------------- | ------------------------------ |
| `CHPW`    | `CHPW`                                      | Change current user's password |
| `USERADD` | `USERADD [USERNAME] [PASSWORD] [AUTH_TYPE]` | Add new user                   |
| `USERDEL` | `USERDEL <USERNAME>`                        | Delete a user                  |
| `USERS`   | `USERS`                                     | List users                     |
| `WHOAMI`  | `WHOAMI`                                    | Show current user              |

> When no parameters are given,`USERADD` prompts the user.
> 
> `AUTH_TYPE` can be one of the following:
> 
> - `admin`
> 
> - `readonly` 

## Other Commands

| Command   | Syntax    | Description           |
| --------- | --------- | --------------------- |
| `COMPACT` | `COMPACT` | Compact the database  |
| `LIST`    | `LIST`    | List database files   |
| `PURGE`   | `PURGE`   | Purge persisted cache |
| `SIZE`    | `SIZE`    | Display database size |


## Functions

### Root Index Functions

| Function   | Syntax              | Description                                                        | Applies to |
| ---------- | ------------------- | ------------------------------------------------------------------ | ---------- |
| `@autoid`  | `@autoid(<INDEX>)`  | Generate a **HKEY** for the given index                            | `W`        |
| `@recall`  | `@recall(<INDEX>)`  | Recall **HKEY**S previously stored with `QQ` (cleared after usage) | `Q`, `W`   |
| `!@recall` | `!@recall(<INDEX>)` | Recall all **HKEY**S excepted the ones previously stored with `QQ` | `Q`, `W`   |
| `@peeq`    | `@peeq(<INDEX>)`    | Same as `@recall` but keeps **HKEY**S in memory                    | `Q`, `W`   |

### Expression Functions

Functions used in field values.

| Function     | Syntax                      | Description                                                     |
| ------------ | ------------------------    | ----------------------------------------------------------------|
| `@abs`       | `@abs[(FIELD)]`             | Absolute value of current field                                 |
| `@date`      | `@date(<FIELD>)`            | Convert a timestamp to a date string                            |
| `@datetime`  | `@datetime(<FIELD>)`        | Convert a timestamp to a date/time string                       |
| `@dec`       | `@dec[(FIELD)]`             | Decrement current field value                                   |
| `@epoch`     | `@epoch[(FIELD|VALUE)]`     | Convert a date string to a timestamp                            |
| `@epochreal` | `@epochreal[(FIELD|VALUE)]` | Convert a date string to a timestamp as a floating-point number |
| `@inc`       | `@inc[(FIELD)]`             | Increment current field value                                   |
| `@neg`       | `@neg[(FIELD)]`             | Negate current field value                                      |
| `@now`       | `@now`                      | Current date/time timestamp                                     |
| `@nowreal`   | `@nowreal`                  | Current date/time as a floating-point number timestamp          |
| `@nowiso`    | `@nowiso`                   | Current date/time as a string                                   |
| `@time`      | `@time(<FIELD>)`            | Convert a timestamp to a time string                            |

> → A *timestamp* is a number of seconds since the Epoch.

### Examples

```
QQ stat album:title=1999 song:title="little red corvette"
W @recall(stat) lastplayed @now playcount @inc
```
> → Update last played time and playcount for the "little red corvette" song.

```
QQ stat album:title=1999
W !@recall(stat) lastplayed null playcount 0
```
> → Set last played time to null and playcount to 0 for all album excepted "1999"

```
Q song:1 title stat:@epoch(lastplayed)
```
> → Convert `lastplayed` date to a Unix timestamp.

```
W transaction:5765 date @epoch(2025-08-06) amount 738.92
```

> → Convert "2025-08-06" to a Unix timestamp.

```
Q transaction @date(date)^2025-08 @[sum:amount]
```

> → Show all transactions for August 2025.

## CLI

```
usage: qdb [-h] [-d] [-p] [-q] [-u username] [-w password] [-v] database [command]

Command Line Interface For the QDB database engine.

positional arguments:
  database              path to the QDB database
  command               QDB command

options:
  -h, --help            show this help message and exit
  -d, --dump            dump database as JSON
  -p, --pipe            reads commands from stdin
  -q, --quiet           be quiet
  -u, --username username
  -w, --password password
  -v, --version         show program's version number and exit

If no option is provided, starts an interactive shell.
```

### Execute a command

```
qdb music.qdb 'Q artist name=kraftwerk album:++date:title'
```

### Pipe commands from a file

```
qdb --pipe music.qdb < data.q
```

→ *Assuming `data.q` contains valid QDB commands*.

### Start an interactive shell

```
qdb music.qdb
QDB version 0.0.1
This program is free software.
It is distributed AS IS with no WARRANTY.

(c) 2025 Stéphane MEYER (Teegre)

-- 43933 hkeys.
-- 23805 references.
-- 42110 referenced hkeys.

[music](+) > Q artist name=kraftwerk album:++date:title
kraftwerk | 1974 | autobahn
kraftwerk | 1975 | radioactivity
kraftwerk | 1977 | trans-europe express
kraftwerk | 1978 | the man machine
kraftwerk | 1981 | computer world
kraftwerk | 1986 | electric café
kraftwerk | 1991 | the mix
kraftwerk | 2003 | tour de france
kraftwerk | 2005 | minimum-maximum
kraftwerk | 2017 | 3-d the catalogue

10 rows found.
Fetched:   0.0987s.
Processed: 0.0017s.
Total:     0.1004s.
```

## Installation

Before proceeding, ensure **python** (version 3.13 or higher), **python-setuptools**, **pipx** and **python-bcrypt** are installed on your system.

### Clone this repository

`git clone https://github.com/teegre/QDB`

### Build QDB

`python -m build`

### Install

`pipx install dist/qdb-0.0.1.tar.gz`

→ *Version number may differ.*

## Try QDB

To give **QDB** a try, a `build_database.sh` script is provided.

It generates a *persons* database with random fake data:

* 10000 persons (index: `person`, fields: name, age, zodiac, address)
* 12 astrological signs (index: `astro`, fields: sign)
* 5000 addresses (index: `address`, fields: street, city)
* 100 cities (index: `city`, fields: name, postcode, country)
* 10 countries (index: `country`, fields: name, code)

The database schema should look similar to:

```
├─ person
│  ├─ address
│  │  ├─ city
│  │  │  ├─ country
│  │  │  │  └─ city (↻)
│  │  │  └─ address (↻)
│  │  └─ person (↻)
│  └─ astro
│     └─ person (↻)
```

To build the example database, run:

`./build_database.sh`

## Uninstall

Are you sure you want to uninstall **QDB**?

`pipx uninstall qdb`
