## migrate-store

This is a small utility to migrate stores from the less-secure scrypt
settings before to the new ones.

The previous scrypt settings used a security setting suitable for
interactive logins (N=2<sup>14</sup>). This will convert a store to
use the setting for long-term storage (N=2<sup>20</sup>).

### Usage

```
migrate-store files...
```


