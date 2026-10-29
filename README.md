# DragonPass

A dragon-themed password generator that runs entirely in your browser. Every password is made with `crypto.getRandomValues`, and nothing is sent anywhere.

**Try it: https://felix-two-tone.github.io/DragonPass/**

## Features

- **Random:** length 4–256 and 14 character sets, including accented letters, Greek and runes. You can exclude look-alike or ambiguous characters, set minimum counts, and require that no characters repeat, no runs like `abc` appear, the password starts with a letter, and more.
- **Passphrase:** common and fantasy word lists, 10 separator styles, 7 capitalisation styles, and digits and symbols you can add.
- **Pronounceable:** passwords built from syllables, with digits and symbols placed where you choose.
- **Pattern:** a template language, e.g. `Cvccvc-d{4}-W`.
- **PIN:** avoids common PINs, years, repeated digits and runs.
- **Keys & Tokens:** hex, Base64, Base64 URL-safe, Base32, Base58 and UUID v4.
- **Strength:** a rating, an entropy figure, and an estimated time to crack for several attacker speeds. A separate tester checks any password you type.
- Generate up to 500 at once, copy them all or download them as `.txt`, and keep a history for the current session.

## Run it

Open `index.html` in a browser. There is no build step.

Or run it with Docker:

```bash
docker compose up -d --build   # http://localhost:8080
docker compose down
```

To use a different port, set `DRAGONPASS_PORT=9002 docker compose up -d`.

## Keyboard shortcuts

`G` generates a new password, `C` copies it, and `H` shows or hides it.
