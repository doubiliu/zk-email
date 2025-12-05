package dkim

import "github.com/doubiliu/zk-email/utils"

var rsaPubkeyTemplate = `v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCl2Qrp5KF1uJnQSO0YuwInVPISQRrUciXtg/5hnQl6ed+UmYvWreLyuiyaiSd9X9Zu+aZQoeKm67HCxSMpC6G2ar0NludsXW69QdfzUpB5I6fzaLW8rl/RyeGkiQ3D66kvadK1wlNfUI7Dt9WtnUs8AFz/15xvODzgTMFJDiAcAwIDAQAB`

var GmailTemplate = utils.FixupNewlines(`to:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
subject:xxxxxxxxxxxxxxx
message-id:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
date:xxx, xx xxx xxxx xx:xx:xx +xxxx (xxx)
from:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
mime-version:1.0
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=xxxxxxxxxx; t=xxxxxxxxxx; x=xxxxxxxxxx; darn=xxxxxxxxxxxxxxxx;
        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Zw3hRkOx46aqHBgt2igwYFtlepgC6pfEZvcSrep7ftU=;
        b=bmJsyZdPshkWt3r/dcQXW5pSN4vS2h7vScI/IyevUlUqsatvPjgffjQmt8ZYzvC/dd
         Zy2WEuIcRhHBhxyOqz2sQgyyBJnpn3XyhxqJErpk06EAzQPyAVGRn8t0AKg3a2Oq4lHf
         UGMnSFM2955aidNpApPoONYSq46zo/sRheBzYKVDFYxvZtE7pv2PG5qHT4k34NWi5S3T
         QeExQ3rgIX2OU4QE3jfxhdo+9i8oHOES80YneT7VfM8CFFxV0N4Hllm7pUvwjJKvgqIt
         FioIk9ArYy79wYUPka3OZ4Xu4okl9vmznBakrYev2yPFdyGoERtZcStiBnUNu290cdeN
         8a6A==`)

var NGDTemplate = utils.FixupNewlines(`To: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Subject: Test
Date: xxx, xx xxx xxxx xx:xx:xx +xxxx (xxx)
Message-id: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MIME-Version: 1.0
Dkim-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=xxxxxxxxxx; bh=ezxyzBzRGSBXS5S4lWvXBCnLY6s83Ja07W1HwKIi4fQ=; h=To:From:Subject:Date:Message-id:Content-Type:MIME-Version:x-icloud-hme; b=gmuFpMQyDOF03EDvmmN2USYrlaASH8Z6hlkd90U7P5/83hGrUs2CEPgQfQWLnSOu9WBNPEx71KFrUY/wyZTJemmrlVjKGZtH74w3hlZV0eosltCfDc07cteVs3k0CImxWokRQlnpzUmI7PZRFhAUXuDX1PbQ1TuFm+onlDd1XAIDSfG4fnGdNdfK23estXJDCJhms7vFQzDX5Fv99LT3a/wi/9w1vV2AtMSiRO55PO1d6EFck0z1+G0o21+iQOpC3PkaPB2xru50QrKKKa4AfNqtCSvLiTHY20bDWHMKGY0292dHMSmF3r9T9PGMMGP3DmnmZfv/tTu+/a00MO9jtg==
`)

var OutlookTemplate = utils.FixupNewlines(`From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Date: xxx, xx xxx xxxx xx:xx:xx +xxxx (xxx)
Subject: xxxxxxxxxxxxxxx
Message-ID: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MIME-Version: 1.0
x-ms-exchange-senderadcheck: 1
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=neo.link; s=xxxxxxxxxx; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck; bh=GGsDC64gLwrxyhYYdbSXAU59KMqyyAQCWjIk7sn+QVo=; b=fCYL+eOzOO0xNLZsZbjaa6lo++gu0ETc67ivaFD48ZLxX8i5Aq9SklhSSIo4S889yWQ0h203A+yVW9bihnW2wohnXW00UzhK2w/XnVANW0KlerWfIhJ447UOoQ5Bk/P9XfUSWszu1R9FU7UJIYJEHD8IGvGPpHeOJQRQ/u0VQ8MliqPgtEo3OVLw1odSNSX/Tukoke8/o1tikxWrcGMYhm+L6Q0KUMg6oPkp+GN4bXZEabKkfGpEQ5/ZnphWlHVKVd3d326QPlZXUBd7smfODnU9VfvmroI9uWcrg/FKCofooSKqSL4TH/W9Rj8Yc/TkZt3aHFZBja4J23NHp0mMaA==`)

var ICloudTemplate = utils.FixupNewlines(`To: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Subject: xxxxxxxxxxxxxxx
Date: xxx, xx xxx xxxx xx:xx:xx +xxxx (xxx)
Message-id: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Content-Type: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MIME-Version: 1.0
Dkim-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=xxxxxxxxxx; bh=ezxyzBzRGSBXS5S4lWvXBCnLY6s83Ja07W1HwKIi4fQ=; h=To:From:Subject:Date:Message-id:Content-Type:MIME-Version:x-icloud-hme; b=gmuFpMQyDOF03EDvmmN2USYrlaASH8Z6hlkd90U7P5/83hGrUs2CEPgQfQWLnSOu9WBNPEx71KFrUY/wyZTJemmrlVjKGZtH74w3hlZV0eosltCfDc07cteVs3k0CImxWokRQlnpzUmI7PZRFhAUXuDX1PbQ1TuFm+onlDd1XAIDSfG4fnGdNdfK23estXJDCJhms7vFQzDX5Fv99LT3a/wi/9w1vV2AtMSiRO55PO1d6EFck0z1+G0o21+iQOpC3PkaPB2xru50QrKKKa4AfNqtCSvLiTHY20bDWHMKGY0292dHMSmF3r9T9PGMMGP3DmnmZfv/tTu+/a00MO9jtg==
`)

var FoxmailTemplate = utils.FixupNewlines(`From: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
To: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
Subject: xxxxxxxxxxxxxxx
Date: xxx, xx xxx xxxx xx:xx:xx +xxxx (xxx)
dkim-signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=foxmail.com; s=xxxxxxxxxx; t=xxxxxxxxxx; bh=puPE4wrCV5YcrcfuFwepbL9s4gzEO/Omu6K0zc+lG5k=; h=From:To:Subject:Date; b=puBeLAmUrZcLTca/kAoDQaW1lUTidBFWtU5oEwIA3dJoeF/8wol9exglsHJFq58budhpmES0VTMpCr4v3rb4TH0gJ+r/Z3k1009nMQlBh3gTWJAG6LUgvXDxlQQBZRM4NlhrgenWw7yebQlbltmOfdY3Uy/mkiidj8fMNEfI3I4=`)
