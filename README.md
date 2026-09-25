# truenas-tang-unlock

Network-bound unlock (NBDE) for TrueNAS encrypted datasets, as a TrueNAS app.

TrueNAS keeps dataset keys on its boot drive, next to the encrypted disks: steal
the box and you steal the keys. The usual alternative is a passphrase typed at
every boot. This app does what clevis/tang does for LUKS: the dataset
passphrase is sealed against a [tang](https://github.com/latchset/tang) server
on your LAN, and only that sealed blob lives on the NAS. At home, datasets
unlock by themselves. Booted anywhere else, the tang server is out of reach and
they stay locked.

Existing guides install clevis into the TrueNAS OS with apt, which means turning
off rootfs protection and redoing it after every upgrade. Here clevis lives in
a container, and the unlock goes through the TrueNAS API.

## How it works

Every `INTERVAL` seconds, the app checks the listed datasets. If one is locked,
it runs `clevis decrypt` on the blob (which only works if the tang server
answers), then calls `pool.dataset.unlock`. TrueNAS then restarts whatever
depends on the dataset: shares, apps.

The passphrase is never passed as an argument or an environment variable. It
goes from `clevis decrypt` to `jq` to `curl` through pipes.

## Layout

The app has to start while the datasets are still locked, so it can't live on
them:

```
tank              unencrypted   TrueNAS apps, this one included
├── media         passphrase    unlocked by this app
└── private       passphrase    unlocked by this app
```

TrueNAS does not allow an encrypted dataset below an unencrypted dataset that
is itself below an encrypted one. Put the encrypted datasets directly under the
unencrypted pool root.

## Setup

1. **API key with a restricted role.** Create a user, a privilege with the
   `DATASET_WRITE` role only, bind the privilege to the user's group, and
   create an API key for that user. `DATASET_WRITE` allows unlocking, locking
   and changing keys, but not deleting datasets or reading files.

2. **Seal the passphrase** on any machine with Docker that can reach tang:

   ```sh
   thp=$(ssh tang-host tang-show-keys 7500)   # the tang signing key thumbprint
   printf %s "$PASSPHRASE" | docker run --rm -i --entrypoint clevis \
     ghcr.io/cbrunie/truenas-tang-unlock encrypt tang \
     "{\"url\":\"http://192.168.1.10:7500\",\"thp\":\"$thp\"}" > passphrase.jwe
   ```

   Give the tang URL as the NAS will see it at boot.

3. **Install the app** from [`compose.example.yaml`](compose.example.yaml) as a
   TrueNAS custom app. Pass the blob and key inline (`JWE`, `TRUENAS_API_KEY`),
   or as files on the unencrypted root readable by UID 65534 (`JWE_FILE`,
   `TRUENAS_API_KEY_FILE`). Inline, they sit in the app config on the
   unencrypted root, like files would: the blob is useless without tang, and
   the key is limited to `DATASET_WRITE`.

## Threat model

- **Protects against:** the NAS stolen on its own, or a disk sent back under
  warranty.
- **Does not protect against:** the tang server stolen along with the NAS.
  Keep them in different places.
- **Keep tang off VPNs.** tang does not authenticate clients. If the stolen NAS
  still joins your Tailscale/WireGuard network and tang listens there, the NAS
  unlocks itself. Bind tang to the LAN address only.
- **Keep an offline copy of the passphrase.** Losing both tang keys and the
  passphrase makes the datasets unreadable.

## Caveats

- A dataset you lock by hand is unlocked again on the next round. Stop the app
  to keep it locked.
- The API is reached over loopback with `-k` (self-signed certificate). To
  reach it elsewhere, set `CURL_CA_BUNDLE`.
- Tested on TrueNAS 25.10, whose REST API is deprecated in favour of the
  WebSocket API.
