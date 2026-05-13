import anthropic
import hexlock

client = anthropic.Anthropic(api_key="YOUR_ANTHROPIC_API_KEY")
# using ephemeral key with hexlock, see docs for stored key
hexlock_client = hexlock.Client()

plain_msg = (
    "I'm getting a 'card declined' error with my credit card 4111-1111-1111-1111 "
    "and my SSN is 123-45-6789 — can you help me troubleshoot why my payment might be failing?"
)

anon_msg = hexlock_client.anonymize(plain_msg)

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": anon_msg}]
)

output_msg = hexlock_client.deanonymize(response.content[0].text)

print(output_msg)
