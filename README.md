# QDB

**QDB** is a lightweight, schema-aware, graph-based database engine with a compact custom query language for fast and expressive data modeling, querying, and traversal. It is designed for structured yet flexible data storage where relationships matter.

## Installation

Ensure **python** (version 3.13 or greater), **python-setuptools** and  **pipx** are installed on your system.

```
$ python --version
Python 3.13.5
$ which pipx
/usr/bin/pipx
```

Clone this repository :

```
$ git clone https://github.com/teegre/QDB
```

Build:

```
$ cd QDB
$ python -m build
```

Then install **QDB** with the following command:

```
$ pipx install dist/qdb-0.0.1.tar.gz
```

*version number may differ*

## 📚 Terminology

| Term              | Description                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------- |
| **Index**         | Represents a type of entity (like a table): e.g., `artist`, `album`, `song`.                 |
| **HKEY**          | A unique hash key identifying an entity. Often in the form `index:id`, e.g., `artist:42`.    |
| **Field**         | A key-value attribute of an entity (e.g., `name`, `title`, `duration`).                      |
| **Reference**     | A relation between two entities (like a foreign key), e.g., a `song` referencing an `album`. |
| **Virtual Field** | Special fields like `@id` (entity ID) and `@hkey` (full key) used in filters.                |
| **Auto ID**       | If not provided, QDB can assign unique IDs with `@autoid(index)` or `W @autoid(...)`.        |

## ✨ Features

- Lightweight

- Dynamic schema inferred from data

- Graph-like navigation across entities

- High-performance flat file storage

- Expressive query language for relational-style filtering, sorting, and joins

- Simple CLI for scripting and data pipelines

- REPL

## 📚 Terminology

QDB uses a few core concepts to represent and relate data:

| Term              | Description                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------- |
| **Index**         | Represents a type of entity (like a table): e.g., `artist`, `album`, `song`.                 |
| **HKEY**          | A unique hash key identifying an entity. Often in the form `index:id`, e.g., `artist:42`.    |
| **Field**         | A key-value attribute of an entity (e.g., `name`, `title`, `duration`).                      |
| **Reference**     | A relation between two entities (like a foreign key), e.g., a `song` referencing an `album`. |
| **Virtual Field** | Special fields like `@id` (entity ID) and `@hkey` (full key) used in filters.                |
| **Auto ID**       | If not provided, QDB can assign unique IDs with `@autoid(index)` or `W @autoid(...)`.        |

## 🔄 Dynamic Schema

Unlike traditional databases, **QDB** does not require a schema to be declared ahead of time. The schema is automatically inferred and evolves as data is added.

When you create a reference from one index to another (e.g., song -> album), that relation becomes part of the schema.

You can inspect the schema at any time with the `schema` command.

References are directional and define the traversal path during queries.

Example:

```
$ qdb music.qdb schema
```

Might output:

```
artist
└── album
 └── song
```

## 🔍 SQL vs QDB

```sql
SELECT artist.name, song.title
FROM artist
JOIN album ON album.artist_id = artist.id
JOIN song ON song.album_id = album.id
WHERE artist.name IN ('Autechre', 'The Cure')
ORDER BY song.title ASC;
```

```
Q artist name(Autechre,"The Cure") song:++title
```

## 🛠️ Example CLI Usage

Start an interactive shell

```
$ qdb music.qdb
```

Batch import from script:

```
$ qdb music.qdb < data.q
```

Add a new artist:

```
$ qdb music.qdb 'W @autoid(artist) name Autechre'
```

Query all albums by a specific artist (sorted by date of release):

```
$ qdb music.qdb 'Q artist name=Autechre album:++date:title'
```

## 🧠 HKEYs and Auto IDs

**QDB** uses keys like `album:5` (HKEYs) to uniquely identify entities. When using `@autoid(index)`, the ID is auto-assigned. HKEYs can be referenced directly when establishing relations:

```
W @autoid(song) title "Montreal" artist artist:1 album album:10
```

## 🧪 Status

**QDB** is an experimental project. It is under active development and suited for use cases requiring embedded graph-style querying with simple dependencies. Feedback and contributions are welcome!
