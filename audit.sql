PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE SYSCALL(aid int, timestamp int, syscall int, success BOOLEAN, exit int, items int, ppid int, pid int, auid int, uid int, gid int, euid int, suid int, fsuid int, egid int, sgid int, fsgid int, tty varchar(10), ses int, comm text, exe text);
CREATE TABLE EXECVE(aid int, timestamp int, argc int, argdata text);
CREATE TABLE PATH(aid int, timestamp int, item int, name text, inode int, dev text, mode text, ouid int, ogid int);
CREATE TABLE CWD(aid int, timestamp int, cwd string);
COMMIT;
