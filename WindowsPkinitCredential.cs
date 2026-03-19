using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using System;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// corrects the mandatory paChecksum field (RFC 4556 §3.2.1 / MS-PKCA §3.2.5.1).
///
/// PA-PK-AS-REQ wire structure (Kerberos.NET 4.x encoding):
///   30 [len]   SEQUENCE          PA-PK-AS-REQ
///     80 [len] [0] PRIMITIVE     signedAuthPack (IMPLICIT ContentInfo)
///       30 ... ContentInfo       the actual CMS SignedData
/// </summary>
public sealed class WindowsPkinitCredential : KerberosAsymmetricCredential
{
    public WindowsPkinitCredential(X509Certificate2 cert, string upn)
        : base(cert, upn) { }

    public override void TransformKdcReq(KrbKdcReq req)
    {
        base.TransformKdcReq(req);  // builds and attaches PA_PK_AS_REQ

        Console.WriteLine($"[DBG] TransformKdcReq: {req.PaData?.Length ?? -1} padata entries after base:");
        if (req.PaData != null)
            foreach (var pd in req.PaData)
                Console.WriteLine($"[DBG]   type={pd.Type} ({(int)pd.Type})  len={pd.Value.Length}");

        InjectPaChecksum(req);

        // Verify the modification actually persisted on req
        int idx = Array.FindIndex(req.PaData ?? Array.Empty<KrbPaData>(),
            p => p.Type == PaDataType.PA_PK_AS_REQ);
        Console.WriteLine($"[DBG] Post-inject PA_PK_AS_REQ len={req.PaData?[idx].Value.Length ?? -1} (should differ from original if re-signed)");
    }

    private void InjectPaChecksum(KrbKdcReq req)
    {
        if (req.PaData is null || req.PaData.Length == 0)
        {
            Console.WriteLine("[DBG] InjectPaChecksum: no PaData");
            return;
        }

        int idx = Array.FindIndex(req.PaData, p => p.Type == PaDataType.PA_PK_AS_REQ);
        Console.WriteLine($"[DBG] PA_PK_AS_REQ index: {idx}");
        if (idx < 0) return;

        // Step 1: Extract CMS from PA-PK-AS-REQ wrapper
        byte[] paValue = req.PaData[idx].Value.ToArray();
        byte[] cmsBytes = ExtractCmsFromPaValue(paValue);
        Console.WriteLine($"[DBG] Extracted CMS ({cmsBytes.Length} bytes), first tag: 0x{cmsBytes[0]:X2}");

        // Step 2: Decode CMS
        var existingCms = new SignedCms();
        existingCms.Decode(cmsBytes);
        Console.WriteLine($"[DBG] CMS decoded. OID={existingCms.ContentInfo.ContentType.Value}");

        // Step 3: Decode KrbAuthPack
        byte[] rawContent = existingCms.ContentInfo.Content;
        Console.WriteLine($"[DBG] CMS Content ({rawContent.Length} bytes), first tag: 0x{rawContent[0]:X2}");
        KrbAuthPack authPack = DecodeAuthPack(rawContent);
        
        if (authPack.PKAuthenticator.PaChecksum.HasValue)
        {
            byte[] existing = authPack.PKAuthenticator.PaChecksum.Value.ToArray();
            Console.WriteLine($"[DBG] Existing paChecksum ({existing.Length} bytes): {Convert.ToHexString(existing)}");
        }
        else
        {
            Console.WriteLine("[DBG] Existing paChecksum: <not set>");
        }

        // Step 4: Compute SHA-1( DER( KDC-REQ-BODY ) ) 
        // We always overwrite — even if already set — because the base
        // class may have computed the checksum over a stale or differently-encoded
        // body snapshot.  Computing here gives us the most up-to-date body bytes.
        byte[] bodyDer = req.Body.Encode().ToArray();
        Console.WriteLine($"[DBG] KDC-REQ-BODY ({bodyDer.Length} bytes):\n{HexDump(bodyDer)}");

        byte[] ourChecksum;
        using (var sha1 = SHA1.Create())
            ourChecksum = sha1.ComputeHash(bodyDer);

        Console.WriteLine($"[DBG] Our computed paChecksum: {Convert.ToHexString(ourChecksum)}");

        // Show whether base-class checksum matches ours
        if (authPack.PKAuthenticator.PaChecksum.HasValue)
        {
            bool match = authPack.PKAuthenticator.PaChecksum.Value.ToArray()
                .SequenceEqual(ourChecksum);
            Console.WriteLine($"[DBG] Existing checksum matches ours: {match}");
        }

        // Step 5: Patch PKAuthenticator
        var pka = authPack.PKAuthenticator;
        pka.PaChecksum = (ReadOnlyMemory<byte>)ourChecksum;
        authPack.PKAuthenticator = pka;

        // Step 6: Re-encode AuthPack
        byte[] newAuthPackDer = authPack.Encode().ToArray();
        Console.WriteLine($"[DBG] Re-encoded AuthPack ({newAuthPackDer.Length} bytes):\n{HexDump(newAuthPackDer)}");

        // Sanity-check: decode the re-encoded pack and confirm paChecksum lives onnnn
        var check = KrbAuthPack.Decode(newAuthPackDer);
        Console.WriteLine($"[DBG] Round-trip paChecksum: {(check.PKAuthenticator.PaChecksum.HasValue ? Convert.ToHexString(check.PKAuthenticator.PaChecksum.Value.ToArray()) : "<missing>")}");

        // Step 7: Re-sign
        var newContent = new ContentInfo(existingCms.ContentInfo.ContentType, newAuthPackDer);
        var newCms = new SignedCms(newContent, detached: false);
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, Certificate)
        {
            IncludeOption = IncludeOption,
            DigestAlgorithm = new Oid("1.3.14.3.2.26"), // id-sha1 hehe
        };
        newCms.ComputeSignature(signer, silent: !CanPrompt);
        byte[] newCmsBytes = newCms.Encode();
        Console.WriteLine($"[DBG] Re-signed CMS ({newCmsBytes.Length} bytes)");

        // Decode the new CMS and verify paChecksum survived the round-trip STOPPPPP BREAKING
        var verifyCms = new SignedCms();
        verifyCms.Decode(newCmsBytes);
        var verifyPack = DecodeAuthPack(verifyCms.ContentInfo.Content);
        Console.WriteLine($"[DBG] paChecksum in re-signed CMS: {(verifyPack.PKAuthenticator.PaChecksum.HasValue ? Convert.ToHexString(verifyPack.PKAuthenticator.PaChecksum.Value.ToArray()) : "<MISSING — CMS lost it>")}");

        // Step 8: Re-wrap and replace padata
        byte[] newPaValue = WrapCmsInPaValue(newCmsBytes);
        Console.WriteLine($"[DBG] Re-wrapped PA-PK-AS-REQ ({newPaValue.Length} bytes)");

        var newPaData = req.PaData.ToArray();
        newPaData[idx] = new KrbPaData { Type = PaDataType.PA_PK_AS_REQ, Value = newPaValue };
        req.PaData = newPaData;
        Console.WriteLine("[DBG] PaData replaced.");
    }

    /// <summary>
    /// Strips the outer SEQUENCE + [0] PRIMITIVE wrapper to get raw ContentInfo bytes.
    /// Input:  30 [len] { 80 [len] { ContentInfo } ... }
    /// Output: ContentInfo bytes starting with 30 ...
    /// </summary>
    private static byte[] ExtractCmsFromPaValue(byte[] paValue)
    {
        var outerReader = new AsnReader(paValue, AsnEncodingRules.BER);
        var seqReader = outerReader.ReadSequence();
        ReadOnlyMemory<byte> tag0Tlv = seqReader.ReadEncodedValue();

        // tag0Tlv = [0] PRIMITIVE TLV — strip tag+length to get value bytes.
        int offset = 1; // skip tag byte
        byte firstLen = tag0Tlv.Span[offset];
        offset += (firstLen & 0x80) == 0
            ? 1                          // short form
            : 1 + (firstLen & 0x7F);    // long form: 1 + N bytes

        return tag0Tlv.Slice(offset).ToArray();
    }

    /// <summary>
    /// Re-wraps CMS bytes into: SEQUENCE { [0] PRIMITIVE { cmsBytes } }
    /// </summary>
    private static byte[] WrapCmsInPaValue(byte[] cmsBytes)
        => BuildBerTlv(0x30, BuildBerTlv(0x80, cmsBytes));

    private static byte[] BuildBerTlv(byte tag, byte[] value)
    {
        using var ms = new MemoryStream(value.Length + 4);
        ms.WriteByte(tag);
        if (value.Length < 128) { ms.WriteByte((byte)value.Length); }
        else if (value.Length <= 0xFF) { ms.WriteByte(0x81); ms.WriteByte((byte)value.Length); }
        else if (value.Length <= 0xFFFF) { ms.WriteByte(0x82); ms.WriteByte((byte)(value.Length >> 8)); ms.WriteByte((byte)(value.Length & 0xFF)); }
        else throw new NotSupportedException($"TLV value too large: {value.Length}");
        ms.Write(value, 0, value.Length);
        return ms.ToArray();
    }

    /// <summary>
    /// Decodes KrbAuthPack, unwrapping any [0] EXPLICIT or OCTET STRING eContent
    /// wrapper that .NET's SignedCms may include for non-standard content OIDs
    /// </summary>
    private static KrbAuthPack DecodeAuthPack(byte[] content)
    {
        Console.WriteLine($"[DBG] DecodeAuthPack: first byte=0x{content[0]:X2}");
        return content[0] switch
        {
            0x30 => KrbAuthPack.Decode(content),
            0xA0 => DecodeFromExplicitWrapper(content),
            0x04 => KrbAuthPack.Decode(new AsnReader(content, AsnEncodingRules.BER).ReadOctetString()),
            _ => KrbAuthPack.Decode(content),
        };
    }

    private static KrbAuthPack DecodeFromExplicitWrapper(byte[] content)
    {
        var outer = new AsnReader(content, AsnEncodingRules.BER);
        var inner = outer.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        var innerTag = inner.PeekTag();
        ReadOnlyMemory<byte> bytes = (innerTag.TagClass == TagClass.Universal && innerTag.TagValue == 4)
            ? inner.ReadOctetString()
            : inner.ReadEncodedValue();
        Console.WriteLine($"[DBG] DecodeAuthPack: unwrapped from [0] EXPLICIT ({bytes.Length} bytes)");
        return KrbAuthPack.Decode(bytes);
    }

    private static string HexDump(byte[] data)
    {
        const int W = 16, MAX = 256;
        int len = Math.Min(data.Length, MAX);
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < len; i += W)
        {
            sb.Append($"  {i:X4}  ");
            int n = Math.Min(W, len - i);
            for (int j = 0; j < W; j++) { if (j < n) sb.Append($"{data[i + j]:X2} "); else sb.Append("   "); if (j == 7) sb.Append(' '); }
            sb.Append(" |");
            for (int j = 0; j < n; j++) { char c = (char)data[i + j]; sb.Append(c >= 32 && c < 127 ? c : '.'); }
            sb.AppendLine("|");
        }
        if (data.Length > MAX) sb.AppendLine($"  ... ({data.Length - MAX} more bytes truncated)");
        return sb.ToString();
    }
}
