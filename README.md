# QDB

A key/value dynamic database manager.

This is work in progress.

## Example

*SQL* Version

```sql
SELECT
  a.id AS artist_id,
  a.name AS artist_name,
  al.title AS album_title,
  al.date AS album_date,
  COUNT(s.id) AS song_count,
  AVG(s.duration) AS avg_duration
FROM artist a
JOIN album al ON al.artist_id = a.id
LEFT JOIN song s ON s.album_id = al.id
WHERE a.id IN (1, 2)
GROUP BY a.id, a.name, al.title, al.date
ORDER BY a.id ASC, al.date ASC;
```

*QDB* version

```
Q artist ++@id(1, 2):name album:title:++date song:@[count:*, avg:duration]
```
