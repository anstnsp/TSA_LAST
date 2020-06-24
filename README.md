
#1.로컬(local, STS)실행
 1) maven install -> run springboot app 
 
 
 #2.개발,운영(dev, prod) 실행 
  1) maven install 
  2) product 폴더를 사용할 서버에 copy 
  3) 해당서버의 product폴더로 이동 
  4) java -jar -Dspring.profiles.active=prod(dev) ./tsa-0.0.1-SNAPSHOT.jar &  