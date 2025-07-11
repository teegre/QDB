# QDB

**QDB** is a lightweight, schema-aware, graph-based **database engine** with a **compact custom query language** for fast and expressive data modeling and querying.

**QDB** is an experimental project under active development.

## Commands

### W: write

Create/Modify fields and values in a hash.

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

### Q: query

Query data.

#### Syntax

`Q <ROOT_INDEX>|<HKEY> [[EXPR1] ... [EXPRN]]`

#### Expression

| Form                 | Description                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `field`              | Display a field from the current index                                                                             |
| `field=value`        | Filter records where `field == value`                                                                              |
| `index:field`        | Follow relationship to another index and display field, use `*` wildcard to display all fields for the given index |
| `index:field=value`  | Filter by value in related index                                                                                   |
| `index:++field`      | Sort results by this field (ascending)                                                                             |
| `index:--field`      | Sort results by this field (descending)                                                                            |
| `index:@[agg:field]` | Aggregation (e.g. `@[count:field]`)                                                                                |

#### Virtual fields

These are *convenience* fields that can be used to display and/or filter data in queries.

| Virtual field | Description                          |
| ------------- | ------------------------------------ |
| `@hkey`       | The full **HKEY**, e.g. `artist:83`  |
| `@id`         | The **ID** part of a HKEY, e.g. `83` |

### Condition operators

| Operator                        | Description           |
| ------------------------------- | --------------------- |
| `=`                             | Equal                 |
| `!=`                            | Not equal             |
| `<`                             | Less than             |
| `<=`                            | Less than or equal    |
| `>`                             | Greater than          |
| `>=`                            | Greater than or equal |
| `^`                             | Starts with           |
| `!^`                            | Does not start with   |
| `$`                             | Ends with             |
| `!$`                            | Does not end with     |
| `**`                            | Contains              |
| `(value1, value2, ..., valueN)` | In                    |
| `!(value1, value2, ... valueN)` | Not in                |

#### Aggregation functions

| Function | Description |
| -------- | ----------- |
| `sum`    | Sum         |
| `avg`    | Average     |
| `min`    | Minimum     |
| `max`    | Maximum     |
| `count`  | Count       |

> *Note: the sorting prefix must be added before the aggregation function.*

#### Examples

**Display all fields for the given index:**

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

