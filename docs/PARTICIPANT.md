# challenege: no nonsense remote access

an abandoned research laboratory has recovered an old remote-access server running a proprietary protocol called SP00KY.

the server has its original users and filesystem, but its administrator credentials have been lost.

you have been given access to a general account.

recover the contents of `/home/admin/flag.txt`.

# access

host: `<HOST>`

port: `19160`

account: `general`

the general private key is supplied as `general.pem`.

```bash
make client
./spooky-client \
    --host <HOST> \
    --port 19160 \
    --user general \
    --key general.pem
```

build dependencies: a c11 compiler and openssl3 development headers (`libssl-dev`).

the client source is yours. you can insepect or reimplement [protocol.md](protocol.md) yourself, but you shouldnt need to.

# on the server

```text
general@spooky:~$
```

the shell implements `help`, `whoami`, `id`, `pwd`, `ls`, `cd`, `cat`, `stat`, `date`, `uname`, and `exit`.

```text
general@spooky:~$ ls
general@spooky:~$ cat welcome.txt
general@spooky:~$ ls /var/log
```

you have access to the general directory and some shared system logs.

the objective is the contents of `/home/admin/flag.txt`.
