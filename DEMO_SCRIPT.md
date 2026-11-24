# Demo script (~1 minute)

A talk track you can say out loud in an interview. Plain language. Practice it once with the app open. You do not need to memorize it word for word.

**Setup:** `./run.sh` is already running. Leave the role on **F&I Manager**, keep the default Lakeside Honda credit application in the prompt box, and click **Run through the proxy** so the four panels are filled before you start talking.

---

## The talk track

“In F&I, a credit application is a deal jacket: Social Security number, date of birth, a card for the deposit, the VIN, and often a bank account for the down payment. You don’t paste that into a random tool, and a dealer group is not going to paste it into a model vendor either. That’s a GLBA-style concern, not a nice-to-have.

This proxy sits in the middle. Before the model ever sees the application, it finds those values and replaces each one with a stable token — the same SSN always becomes the same token for this store, so the model can still refer to it. What you’re looking at on the right is what the model actually saw: tokens, not the raw numbers.

The model writes a short review using those tokens. Because I’m signed in here as the F&I manager, the last panel puts the real values back so I can check them against the jacket. If I switch this dropdown to a sales consultant and run it again, they still get the review, but the numbers stay tokenized. They’re not supposed to walk out of the desk with a customer’s SSN.

And every mask and unmask is written to an append-only log: the token, the type, who, and when — never the raw value. If someone edits a past line, the hash chain breaks, and `verify-chain` catches it.”

---

## Timing notes

Spoken at a normal pace, that is about 50–60 seconds. If you have a few extra seconds, point at one concrete pair — the SSN in the original prompt and the `[PII_SSN_…]` token in “what the model saw” — then stop and let them ask questions.

If you have two minutes, switch the role to **Sales Consultant**, run it again, and show that the delivered panel does not unmask. That contrast is the easiest thing for a non-technical interviewer to remember.

## If they ask a follow-up

- **“Why not just use ChatGPT and turn on some privacy setting?”**  
  “Because the customer’s rule is usually ‘this data does not leave our environment, and it does not go to the vendor.’ A proxy you control, in front of whatever model they already approved, is a much easier conversation than asking them to trust a vendor-side filter.”

- **“How do you know the tokens are deterministic?”**  
  “They’re HMAC-derived from the tenant, the type, and the normalized value. `219-09-9999` and `219099999` become the same token inside Lakeside Auto Group, and a different group gets a different token for the same number, so stores can’t join records by comparing tokens.”

- **“Will regex catch everything?”**  
  “No, and I say that in the README. A card number split across lines, an SSN written in words, a name with no label — those can slip through. That’s why I’d put a real DLP engine like Presidio next to these rules in production, and why I would never call this a certified control.”

- **“Where is the raw SSN stored?”**  
  “In a local vault, encrypted with Fernet. The audit log only has the token and the type. In production that key would live in a KMS or HSM, not a file named `demo.keys`.”

- **“What if I want to use a real model?”**  
  “There’s an optional OpenAI-compatible hook, off by default. Point `PII_PROXY_LLM_BASE_URL` at a local Ollama or an approved endpoint. The default path is a mock so this demo runs on a laptop with no account and no bill.”

- **“Is this GLBA / PCI compliant?”**  
  “No. It’s a teaching demo of the pattern. Compliance would mean a real DLP review, key management, SSO, retention, and the customer’s own assessors. I would never tell a dealer this repo makes them compliant.”

- **“What would you do on a real dealer group?”**  
  “Agree the list of fields that must never leave the store — SSN, PAN, bank account, DL, and anything in the deal jacket that identifies a buyer. Put this proxy in front of the approved model. Wire unmasking to their actual roles in the DMS or SSO, not a dropdown. And let compliance pull the hash-chained audit without ever downloading a file full of Social Security numbers.”
