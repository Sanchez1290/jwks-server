### AI Support Disclosure

ChatGPT (OpenAI) was used as a learning and troubleshooting tool while working on this project.
It helped me better understand JWKS/JWT concepts (such as `kid` values, key expiration, and JWKS formatting) and provided guidance when I got stuck during implementation.
I mainly used it to ask questions about endpoint behavior, debugging issues, and testing ideas. Example prompts included: “How should a JWKS server return public keys?”, “How does a JWT include a kid in the header?”, and “Why might my JWT validation fail?”.
All coding, implementation, testing, and final project decisions were completed by me.

This part of the project explores the use of AI support to gain a better understanding of implementing a JWKS server backed by SQLite. I used AI guidance to clarify concepts, plan the code structure, and troubleshoot implementation steps. During testing, I attempted to run the included Gradebot client; however, my Mac initially did not trust the client, so I was unable to fully test it on my machine. Despite this, the project demonstrates the intended functionality of signing JWTs, storing keys in SQLite, and serving a JWKS endpoint.
