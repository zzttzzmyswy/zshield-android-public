package top.zztweb.zshield.ui.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp

/**
 * The handful of glyphs the app needs that are not in Compose's built-in set (paths from Material
 * Symbols, Apache-2.0). Declared here instead of pulling `material-icons-extended`.
 */
object AppIcons {
    private fun icon(name: String, vararg paths: String, evenOdd: Boolean = false): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
            paths.forEach { d ->
                addPath(
                    pathData = addPathNodes(d),
                    fill = SolidColor(Color.Black),
                    pathFillType = if (evenOdd) PathFillType.EvenOdd else PathFillType.NonZero,
                )
            }
        }.build()

    val Shield: ImageVector by lazy {
        icon("Shield", "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4z")
    }

    val ShieldOutline: ImageVector by lazy {
        icon(
            "ShieldOutline",
            "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4zM19,11c0,4.52 -2.98,8.69 -7,9.93 " +
                "-4.02,-1.24 -7,-5.41 -7,-9.93V6.3l7,-3.11 7,3.11V11z",
        )
    }

    val ShieldCheck: ImageVector by lazy {
        icon(
            "ShieldCheck",
            "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5L12,1zM10,17l-4,-4 1.41,-1.41L10,14.17" +
                "l6.59,-6.59L18,9l-8,8z",
        )
    }

    val FilterAlt: ImageVector by lazy {
        icon(
            "FilterAlt",
            "M4.25,5.61C6.27,8.2 10,13 10,13v6c0,0.55 0.45,1 1,1h2c0.55,0 1,-0.45 1,-1v-6c0,0 3.72,-4.8 5.74,-7.39" +
                "C20.25,4.95 19.78,4 18.95,4H5.04C4.21,4 3.74,4.95 4.25,5.61z",
        )
    }

    val Apps: ImageVector by lazy {
        icon(
            "Apps",
            "M4,8h4V4H4v4zM10,20h4v-4h-4v4zM4,20h4v-4H4v4zM4,14h4v-4H4v4zM10,14h4v-4h-4v4zM16,4v4h4V4h-4z" +
                "M10,8h4V4h-4v4zM16,14h4v-4h-4v4zM16,20h4v-4h-4v4z",
        )
    }

    /** Receipt-style list, for the request log tab. */
    val ReceiptLong: ImageVector by lazy {
        icon(
            "ReceiptLong",
            "M19.5,3.5L18,2l-1.5,1.5L15,2l-1.5,1.5L12,2l-1.5,1.5L9,2L7.5,3.5L6,2v14H3v3c0,1.66 1.34,3 3,3h12" +
                "c1.66,0 3,-1.34 3,-3V2L19.5,3.5zM19,19c0,0.55 -0.45,1 -1,1s-1,-0.45 -1,-1v-3H8V5h11V19z",
            "M9,7h6v2h-6z", "M16,7h2v2h-2z", "M9,10h6v2h-6z", "M16,10h2v2h-2z",
        )
    }

    val Block: ImageVector by lazy {
        icon(
            "Block",
            "M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM4,12c0,-4.42 3.58,-8 8,-8 " +
                "1.85,0 3.55,0.63 4.9,1.69L5.69,16.9C4.63,15.55 4,13.85 4,12zM12,20c-1.85,0 -3.55,-0.63 -4.9,-1.69" +
                "L18.31,7.1C19.37,8.45 20,10.15 20,12c0,4.42 -3.58,8 -8,8z",
        )
    }

    val Dns: ImageVector by lazy {
        icon(
            "Dns",
            "M20,13H4c-0.55,0 -1,0.45 -1,1v6c0,0.55 0.45,1 1,1h16c0.55,0 1,-0.45 1,-1v-6c0,-0.55 -0.45,-1 -1,-1z" +
                "M7,19c-1.1,0 -2,-0.9 -2,-2s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2zM20,3H4C3.45,3 3,3.45 3,4v6" +
                "c0,0.55 0.45,1 1,1h16c0.55,0 1,-0.45 1,-1V4c0,-0.55 -0.45,-1 -1,-1zM7,9c-1.1,0 -2,-0.9 -2,-2" +
                "s0.9,-2 2,-2 2,0.9 2,2 -0.9,2 -2,2z",
        )
    }

    val SwapVert: ImageVector by lazy {
        icon("SwapVert", "M16,17.01V10h-2v7.01h-3L15,21l4,-3.99h-3zM9,3L5,6.99h3V14h2V6.99h3L9,3z")
    }

    val Language: ImageVector by lazy {
        icon(
            "Language",
            "M11.99,2C6.47,2 2,6.48 2,12s4.47,10 9.99,10C17.52,22 22,17.52 22,12S17.52,2 11.99,2zM18.92,8h-2.95" +
                "c-0.32,-1.25 -0.78,-2.45 -1.38,-3.56 1.84,0.63 3.37,1.91 4.33,3.56zM12,4.04c0.83,1.2 1.48,2.53 " +
                "1.91,3.96h-3.82c0.43,-1.43 1.08,-2.76 1.91,-3.96zM4.26,14C4.1,13.36 4,12.69 4,12s0.1,-1.36 " +
                "0.26,-2h3.38c-0.08,0.66 -0.14,1.32 -0.14,2s0.06,1.34 0.14,2H4.26zM5.08,16h2.95c0.32,1.25 " +
                "0.78,2.45 1.38,3.56 -1.84,-0.63 -3.37,-1.9 -4.33,-3.56zM8.03,8H5.08c0.96,-1.66 2.49,-2.93 " +
                "4.33,-3.56C8.81,5.55 8.35,6.75 8.03,8zM12,19.96c-0.83,-1.2 -1.48,-2.53 -1.91,-3.96h3.82" +
                "c-0.43,1.43 -1.08,2.76 -1.91,3.96zM14.34,14H9.66c-0.09,-0.66 -0.16,-1.32 -0.16,-2s0.07,-1.35 " +
                "0.16,-2h4.68c0.09,0.65 0.16,1.32 0.16,2s-0.07,1.34 -0.16,2zM14.59,19.56c0.6,-1.11 1.06,-2.31 " +
                "1.38,-3.56h2.95c-0.96,1.65 -2.49,2.93 -4.33,3.56zM16.36,14c0.08,-0.66 0.14,-1.32 0.14,-2" +
                "s-0.06,-1.34 -0.14,-2h3.38c0.16,0.64 0.26,1.31 0.26,2s-0.1,1.36 -0.26,2h-3.38z",
        )
    }

    val Bug: ImageVector by lazy {
        icon(
            "Bug",
            "M20,8h-2.81c-0.45,-0.78 -1.07,-1.45 -1.82,-1.96L17,4.41 15.59,3l-2.17,2.17C12.96,5.06 12.49,5 12,5" +
                "c-0.49,0 -0.96,0.06 -1.41,0.17L8.41,3 7,4.41l1.62,1.63C7.88,6.55 7.26,7.22 6.81,8H4v2h2.09" +
                "c-0.05,0.33 -0.09,0.66 -0.09,1v1H4v2h2v1c0,0.34 0.04,0.67 0.09,1H4v2h2.81c1.04,1.79 2.97,3 5.19,3" +
                "s4.15,-1.21 5.19,-3H20v-2h-2.09c0.05,-0.33 0.09,-0.66 0.09,-1v-1h2v-2h-2v-1c0,-0.34 -0.04,-0.67 " +
                "-0.09,-1H20V8zM14,16h-4v-2h4v2zM14,12h-4v-2h4v2z",
        )
    }

    val Upload: ImageVector by lazy {
        icon("Upload", "M5,20h14v-2H5V20zM5,10h4v6h6v-6h4l-7,-7L5,10z")
    }

    val Link: ImageVector by lazy {
        icon(
            "Link",
            "M3.9,12c0,-1.71 1.39,-3.1 3.1,-3.1h4V7H7c-2.76,0 -5,2.24 -5,5s2.24,5 5,5h4v-1.9H7c-1.71,0 -3.1,-1.39 " +
                "-3.1,-3.1zM8,13h8v-2H8v2zM17,7h-4v1.9h4c1.71,0 3.1,1.39 3.1,3.1s-1.39,3.1 -3.1,3.1h-4V17h4" +
                "c2.76,0 5,-2.24 5,-5s-2.24,-5 -5,-5z",
        )
    }
}
