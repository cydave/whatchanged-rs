# whatchanged

Rust learning project.


```
$ cat sha256sum.txt

1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2  data/3.txt
2e6d31a5983a91251bfae5aefa1c0a19d8ba3cf601d0e8a706b4cfa9661a6b8a  data/9.txt
10159baf262b43a92d95db59dae1f72c645127301661e0a3ce4e38b295a97c58  data/7.txt
06e9d52c1720fca412803e3b07c4b228ff113e303f4c7ab94665319d832bbfb7  data/6.txt
53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3  data/2.txt
f0b5c2c2211c8d67ed15e75e656c7862d086e9245420892a7de62cd9ec582a06  data/5.txt
917df3320d778ddbaa5c5c7742bc4046bf803c36ed2b050f30844ed206783469  data/10.txt
4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865  data/1.txt
7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d  data/4.txt
aa67a169b0bba217aa0aa88a65346920c84c42447c36ba5f7ea65f422c1fe5d8  data/8.txt
```


```
$ cargo run

data/3.txt: OK
data/9.txt: MISMATCH
data/7.txt: OK
data/6.txt: REMOVED
data/2.txt: OK
data/5.txt: OK
data/10.txt: OK
data/1.txt: MISMATCH
data/4.txt: OK
data/8.txt: OK
WARNING: 1 file has been removed
WARNING: 2 checksums did NOT match
```
