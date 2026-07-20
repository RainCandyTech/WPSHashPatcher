package tech.youko.wpshashpatcher

import java.nio.ByteBuffer

fun findPattern(
    data: ByteBuffer,
    pattern: IntArray,
    mask: IntArray = IntArray(pattern.size),
    index: Int = data.position(),
    reverse: Boolean = false,
    maxMatches: Int = Int.MAX_VALUE
): List<Int> {
    require(pattern.size == mask.size) { "Pattern and mask must have the same size." }
    require(pattern.all { it in 0..0xFF } && mask.all { it in 0..0xFF }) {
        "Pattern and mask values must be unsigned bytes."
    }
    val matches = mutableListOf<Int>()
    val start = if (reverse) minOf(data.limit() - pattern.size, index) else maxOf(0, index)
    val range = if (reverse) start downTo 0 else start..data.limit() - pattern.size

    for (i in range) {
        if (pattern.indices.all { j ->
                val actual = data[i + j].toInt() and 0xFF
                ((actual xor pattern[j]) and (mask[j] xor 0xFF)) == 0
            }) {
            matches.add(i)
            if (matches.size >= maxMatches) break
        }
    }
    return matches
}

fun bytesOf(vararg values: Int): ByteArray = values.map(Int::toByte).toByteArray()

fun ByteArray.toPattern(): IntArray = map { it.toUByte().toInt() }.toIntArray()
