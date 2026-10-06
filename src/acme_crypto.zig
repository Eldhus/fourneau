//! The cryptography of ACME (RFC 8555), apart from its HTTP: ECDSA P-256
//! keys, the account key as a JWK and its thumbprint (RFC 7638), requests
//! signed as JWS with ES256 (RFC 7515), the certificate signing request
//! (PKCS #10, RFC 2986) naming one IP address or DNS name, and the
//! certificate key as SEC1 PEM for tls.zig to load. All into fixed buffers.

const std = @import("std");
const assert = std.debug.assert;
const der = @import("der.zig");

const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64url = std.base64.url_safe_no_pad;

pub const KeyPair = Ecdsa.KeyPair;
pub const secret_key_bytes = Ecdsa.SecretKey.encoded_length;

/// What a certificate names: an IP address (as Let's Encrypt's short-lived
/// IP certificates do) or a DNS name.
pub const Identifier = union(enum) {
    ip: std.Io.net.IpAddress,
    dns: []const u8,

    /// The value as ACME's JSON names it.
    pub fn format_value(identifier: Identifier, buffer: []u8) ![]const u8 {
        return switch (identifier) {
            .ip => |address| switch (address) {
                // Zig's formatter appends the port; ACME wants the address.
                .ip4 => |ip4| std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{
                    ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
                }) catch |err| switch (err) {
                    error.NoSpaceLeft => error.IdentifierTooLong,
                },
                .ip6 => error.Ip6NotSupported,
            },
            .dns => |name| name,
        };
    }

    pub fn kind(identifier: Identifier) []const u8 {
        return switch (identifier) {
            .ip => "ip",
            .dns => "dns",
        };
    }
};

/// `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`: members in lexicographic
/// order and no whitespace, which the thumbprint requires.
pub fn jwk(key_pair: KeyPair, buffer: []u8) ![]const u8 {
    const point = key_pair.public_key.toUncompressedSec1();
    assert(point[0] == 0x04);
    var x: [base64url.Encoder.calcSize(32)]u8 = undefined;
    var y: [base64url.Encoder.calcSize(32)]u8 = undefined;
    _ = base64url.Encoder.encode(&x, point[1..33]);
    _ = base64url.Encoder.encode(&y, point[33..65]);
    const template = "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}";
    return std.fmt.bufPrint(buffer, template, .{
        x, y,
    });
}

/// base64url(SHA-256(jwk)): the account's name in a key authorization.
pub fn thumbprint(key_pair: KeyPair) [base64url.Encoder.calcSize(Sha256.digest_length)]u8 {
    var jwk_buffer: [256]u8 = undefined;
    const text = jwk(key_pair, &jwk_buffer) catch unreachable; // 256 > the JWK's ~130 bytes
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(text, &digest, .{});
    var encoded: [base64url.Encoder.calcSize(Sha256.digest_length)]u8 = undefined;
    _ = base64url.Encoder.encode(&encoded, &digest);
    return encoded;
}

/// Who signs: before the account exists, its key itself (`jwk`); after,
/// the account's URL (`kid`).
pub const Signer = union(enum) {
    jwk,
    kid: []const u8,
};

/// A JWS in flattened JSON: {"protected":…,"payload":…,"signature":…}.
/// An empty payload is POST-as-GET.
pub fn sign_request(
    key_pair: KeyPair,
    signer: Signer,
    nonce: []const u8,
    url: []const u8,
    payload: []const u8,
    buffer: []u8,
) ![]const u8 {
    var header_buffer: [1024]u8 = undefined;
    const header = switch (signer) {
        .jwk => blk: {
            var jwk_buffer: [256]u8 = undefined;
            const key = try jwk(key_pair, &jwk_buffer);
            break :blk try std.fmt.bufPrint(&header_buffer,
                \\{{"alg":"ES256","jwk":{s},"nonce":"{s}","url":"{s}"}}
            , .{ key, nonce, url });
        },
        .kid => |kid| try std.fmt.bufPrint(&header_buffer,
            \\{{"alg":"ES256","kid":"{s}","nonce":"{s}","url":"{s}"}}
        , .{ kid, nonce, url }),
    };
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeAll("{\"protected\":\"");
    const protected_start = writer.end;
    try base64url.Encoder.encodeWriter(&writer, header);
    const protected_end = writer.end;
    try writer.writeAll("\",\"payload\":\"");
    const payload_start = writer.end;
    try base64url.Encoder.encodeWriter(&writer, payload);
    const payload_end = writer.end;
    // The signature covers `protected.payload`, both as encoded.
    var signing_input = try key_pair.signer(null);
    signing_input.update(buffer[protected_start..protected_end]);
    signing_input.update(".");
    signing_input.update(buffer[payload_start..payload_end]);
    const signature = try signing_input.finalize();
    try writer.writeAll("\",\"signature\":\"");
    try base64url.Encoder.encodeWriter(&writer, &signature.toBytes());
    try writer.writeAll("\"}");
    return writer.buffered();
}

/// `token.thumbprint`: what an http-01 challenge serves.
pub fn key_authorization(token: []const u8, account: KeyPair, buffer: []u8) ![]const u8 {
    const print = thumbprint(account);
    return std.fmt.bufPrint(buffer, "{s}.{s}", .{ token, &print });
}

/// A PKCS #10 request for one identifier, signed by the certificate's key:
/// DER, for `finalize` (base64url) to carry.
pub fn csr(key_pair: KeyPair, identifier: Identifier, buffer: []u8) ![]const u8 {
    var info_buffer: [512]u8 = undefined;
    var info = der.Writer.init(&info_buffer);
    try write_request_info(&info, key_pair, identifier);
    const info_bytes = info.bytes();
    const signature = try key_pair.sign(info_bytes, null);
    var signature_der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;

    var writer = der.Writer.init(buffer);
    try writer.begin(.sequence);
    try writer.raw(info_bytes);
    try writer.begin(.sequence);
    try writer.raw(&der.oid.ecdsa_with_sha256);
    try writer.end_value();
    try writer.bit_string(signature.toDer(&signature_der));
    try writer.end_value();
    return writer.bytes();
}

fn write_request_info(writer: *der.Writer, key_pair: KeyPair, identifier: Identifier) !void {
    try writer.begin(.sequence);
    try writer.small_integer(0); // version 1
    try writer.begin(.sequence); // subject: empty, the name is in the SAN
    try writer.end_value();
    try write_public_key_info(writer, key_pair);
    try writer.begin(der.Tag.context_constructed(0)); // attributes
    try writer.begin(.sequence);
    try writer.raw(&der.oid.extension_request);
    try writer.begin(.set);
    try writer.begin(.sequence); // Extensions
    try writer.begin(.sequence); // Extension
    try writer.raw(&der.oid.subject_alt_name);
    try writer.begin(.octet_string);
    try write_general_names(writer, identifier);
    try writer.end_value();
    try writer.end_value();
    try writer.end_value();
    try writer.end_value();
    try writer.end_value();
    try writer.end_value();
    try writer.end_value();
}

fn write_public_key_info(writer: *der.Writer, key_pair: KeyPair) !void {
    try writer.begin(.sequence);
    try writer.begin(.sequence);
    try writer.raw(&der.oid.ec_public_key);
    try writer.raw(&der.oid.prime256v1);
    try writer.end_value();
    try writer.bit_string(&key_pair.public_key.toUncompressedSec1());
    try writer.end_value();
}

fn write_general_names(writer: *der.Writer, identifier: Identifier) !void {
    try writer.begin(.sequence);
    switch (identifier) {
        .ip => |address| {
            const ip4 = switch (address) {
                .ip4 => |ip4| ip4,
                .ip6 => return error.Ip6NotSupported,
            };
            try writer.value(der.Tag.context_primitive(7), &ip4.bytes);
        },
        .dns => |name| try writer.value(der.Tag.context_primitive(2), name),
    }
    try writer.end_value();
}

/// SEC1 ECPrivateKey in PEM ("EC PRIVATE KEY"), which tls.zig loads.
pub fn private_key_pem(key_pair: KeyPair, buffer: []u8) ![]const u8 {
    var der_buffer: [160]u8 = undefined;
    var writer = der.Writer.init(&der_buffer);
    try writer.begin(.sequence);
    try writer.small_integer(1);
    try writer.value(.octet_string, &key_pair.secret_key.toBytes());
    try writer.begin(der.Tag.context_constructed(0));
    try writer.raw(&der.oid.prime256v1);
    try writer.end_value();
    try writer.begin(der.Tag.context_constructed(1));
    try writer.bit_string(&key_pair.public_key.toUncompressedSec1());
    try writer.end_value();
    try writer.end_value();
    return pem("EC PRIVATE KEY", writer.bytes(), buffer);
}

/// PEM: base64 in 64-column lines between the label's armor.
pub fn pem(label: []const u8, bytes: []const u8, buffer: []u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.print("-----BEGIN {s}-----\n", .{label});
    var encoded_buffer: [4096]u8 = undefined;
    const encoder = std.base64.standard.Encoder;
    if (encoder.calcSize(bytes.len) > encoded_buffer.len) return error.PemTooLarge;
    const encoded = encoder.encode(&encoded_buffer, bytes);
    var start: usize = 0;
    while (start < encoded.len) : (start += 64) {
        const line = encoded[start..@min(start + 64, encoded.len)];
        try writer.print("{s}\n", .{line});
    }
    try writer.print("-----END {s}-----\n", .{label});
    return writer.buffered();
}

test "acme_crypto: a JWS verifies over its protected header and payload" {
    const key_pair = try KeyPair.generateDeterministic(@splat(7));
    var buffer: [2048]u8 = undefined;
    const jws = try sign_request(key_pair, .jwk, "nonce-1", "https://ca/new-acct", "{}", &buffer);
    var parsed = try std.json.parseFromSlice(struct {
        protected: []const u8,
        payload: []const u8,
        signature: []const u8,
    }, std.testing.allocator, jws, .{});
    defer parsed.deinit();
    var signature_bytes: [64]u8 = undefined;
    try base64url.Decoder.decode(&signature_bytes, parsed.value.signature);
    const signature = Ecdsa.Signature.fromBytes(signature_bytes);
    var verifier = try signature.verifier(key_pair.public_key);
    verifier.update(parsed.value.protected);
    verifier.update(".");
    verifier.update(parsed.value.payload);
    try verifier.verify();
}

test "acme_crypto: the thumbprint is over the canonical JWK" {
    const key_pair = try KeyPair.generateDeterministic(@splat(9));
    var buffer: [256]u8 = undefined;
    const text = try jwk(key_pair, &buffer);
    const start = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"";
    try std.testing.expect(std.mem.startsWith(u8, text, start));
    try std.testing.expect(std.mem.indexOfScalar(u8, text, ' ') == null);
    const print = thumbprint(key_pair);
    try std.testing.expectEqual(@as(usize, 43), print.len);
}

test "acme_crypto: a CSR for an IP address, and the key as SEC1 PEM" {
    const key_pair = try KeyPair.generateDeterministic(@splat(11));
    var csr_buffer: [1024]u8 = undefined;
    const address = try std.Io.net.IpAddress.parse("203.0.113.7", 0);
    const request = try csr(key_pair, .{ .ip = address }, &csr_buffer);
    try std.testing.expectEqual(@as(u8, 0x30), request[0]); // a SEQUENCE
    // The IP address, as GeneralName [7] with its four bytes.
    const san = [_]u8{ 0x87, 0x04, 203, 0, 113, 7 };
    try std.testing.expect(std.mem.indexOf(u8, request, &san) != null);
    var pem_buffer: [512]u8 = undefined;
    const key = try private_key_pem(key_pair, &pem_buffer);
    try std.testing.expect(std.mem.startsWith(u8, key, "-----BEGIN EC PRIVATE KEY-----\n"));
    var value_buffer: [64]u8 = undefined;
    const value = try (Identifier{ .ip = address }).format_value(&value_buffer);
    try std.testing.expectEqualStrings("203.0.113.7", value);
}
