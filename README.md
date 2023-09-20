 <div align="center">
  </br>
  <p>
    <img height="50" src="assets/logo.png" />
  </p>
  <p>
    <strong>Bankmen Finance Scraper Utilities</strong>
  </p>
  <p>
    <!-- <a href="https://discord.gg/jr9Mu4Uz25">
      <img alt="Discord Chat" src="https://img.shields.io/discord/880917405356945449?color=blue&style=flat-square" />
    </a> -->
  </p>
</div>

This repository contains utilities used to build transaction scrapers for Solana programs.

---

## Dependencies

Due to usage of solana v1.16+ and anchor v0.28 this project requires rustc 1.68+, therefore the `.vscode/settings.json` is pinned to `stable` rust toolchain.

To make sure you have the latest stable toolchain:

```rustup update && rustup upgrade```

If you are using a different default toolchain and would not like to change the global default toolchain:

```rustup override set stable``` 

The command above will override the settings for the `scraper-utils` directory.

---
