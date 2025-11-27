# Socket_Proxy_server  
System-level Socket Proxy Server for Linux

## 개요  

Socket_Proxy_server는 Linux 환경에서 C 언어 기반 소켓 프로그래밍을 통해 구현한 프록시 서버입니다.  
클라이언트의 요청을 중계하고, 캐시 및 동시 처리 제어 기능을 포함하여 HTTP 기반 통신을 프록시 서버가 대신 처리합니다.  

- 클라이언트 ↔ 서버 간 HTTP 요청/응답을 중계  
- URL caching을 통해 동일 요청에 대해 응답 속도 향상  
- 동시 접속 시 lock / semaphore 기반 동시성 제어  
- 예외 발생 시 알람(signal) 처리 및 오류 페이지 제공  
- 프록시 서버 구조 설계 경험을 통한 네트워크/OS-레벨 이해  

---

## 주요 기능  

- **프록시 중계 (Proxy Forwarding)**  
  클라이언트의 http 요청을 받아 원격 서버로 전달하고, 응답을 다시 클라이언트에 반환합니다.
  <img width="650" height="719" alt="image" src="https://github.com/user-attachments/assets/38c4cfcb-8777-47ba-a15c-1a8d4de11d64" />


- **URL 캐싱 (Caching Proxy)**  
  이전에 접속한 적이 있던 url을 파일 시스템에 저장한 후, 동일한 요청이 반복될 경우
  SHA1 방식으로 해싱된 url을 복호화하여캐시된 응답을 바로 제공하여 서버 부하와 지연을 줄입니다.
  <img width="721" height="1029" alt="image" src="https://github.com/user-attachments/assets/c6ea6b37-49ff-4b90-aafe-ff1a30945ffd" />


- **동시 접속 처리 및 안정성 보장**  
  lock / semaphore를 이용하여 다수 클라이언트의 동시 요청을 제어하고, race condition, 데이터 손상 방지를 구현합니다.  

- **예외 및 오류 처리**  
  알람(signal) 기반 예외 처리를 통해 오류 발생 시 적절한 오류 페이지를 반환하고, 서버의 안정적인 동작을 유지합니다.  

- **경량 및 단순 설계**  
  외부 프레임워크 없이 순수 C + 시스템 콜 기반으로 구현되어, OS-레벨 네트워크 프로그래밍 연습에 적합합니다.  

---

## 🛠 빌드 & 실행 방법  

# 소스 다운로드  
git clone https://github.com/425range/Socket_Proxy_server.git  
cd Socket_Proxy_server  

# 빌드  
make  

# 실행 (포트 8080 등)
./proxy_cache <listen_port>  

# 이후 브라우저 또는 HTTP 클라이언트에서
# localhost:<listen_port>를 프록시로 설정하면 동작합니다.


## 활용 사례 및 확장 아이디어

본 프로젝트를 통해 프록시 서버 구조 이해 및 네트워크 기초를 다졌습니다.

향후 HTTPS / SSL 터널링, HTTP/2, 멀티스레드 또는 비동기 I/O 기반으로 확장이 가능합니다.
