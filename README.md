# PingSweep

PingSweepは、指定されたIP範囲のアクティブなデバイスを検出するPythonスクリプトです。

## 特徴

- 指定されたIP範囲内の生きているホストを識別します。
- 新規で見つかったホスト、接続が切れたホスト、変化がないホストを色分けして表示します。
- スキャン結果をファイルに保存し、次回スキャン時に以前の結果と比較します。

## 使い方

特定の範囲を指定してスキャンする場合:
```bash
python3 pingsweep.py 192.168.1.0/24
```

自動でローカルIP範囲を検出してスキャンする場合:
```bash
python3 pingsweep.py
```

## インストール

1. 必要なPythonライブラリをインストールします:
    ```bash
    pip install pythonping
    pip install tqdm
    pip install termcolor
    ```

## 実行例

ローカルネットワーク（192.168.1.0/24）をスキャンした場合の出力例です:

```bash
$ python3 pingsweep.py 192.168.1.0/24
Scanning 192.168.1.1: 100%|███████████████████████████████████████████████████████████| 254/254 [00:25<00:00, 10.12host/s]

Alive hosts:
192.168.1.1 (myrouter.local)  # 以前からあるホスト (白)
192.168.1.2 (newdevice.local)  # 新規ホスト (緑)
192.168.1.5  # 自端末 (青)
... その他のホスト ...
```


2. スクリプトをダウンロードし、実行権限を与えます（必要な場合）。

## ライセンス

このプロジェクトはMITライセンスのもとで公開されています。詳細はLICENSEファイルをご覧ください。
