from service import Service

# Create and save the keys
s = Service()
s.save_keys()

print("✅ Keys saved to disk as 'service_private.pem' and 'service_public.pem'")
