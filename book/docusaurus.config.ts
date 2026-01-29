import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import remarkMath from "remark-math";
import rehypeKatex from "rehype-katex";

// KaTeX macros converted from macros.txt
const katexMacros = {
  "\\sample": "{\\stackrel{{\\tiny \\$}}{\\ \\gets\\ }}",
  "\\GG": "{\\mathbb{G}}",
  "\\FF": "{\\mathbb{F}}",
  "\\language": "{\\mathcal{L}}",
  "\\relation": "{\\mathcal{R}}",
  "\\witness": "{\\text{w}}",
  "\\statement": "{\\text{x}}",
  "\\chalfold": "{\\alpha}",
  "\\chaleval": "{\\zeta}",
  "\\chalu": "{u}",
  "\\chalv": "{v}",
  "\\openx": "{x}",
  "\\openy": "{y}",
  "\\comm": "{C}",
  "\\accCom": "{U}",
  "\\accChal": "{\\chalfold}",
  "\\genOpen": "{H}",
  "\\hpoly": "{h}",
  "\\relAcc": "{\\relation_{\\mathsf{Acc},\\vec{G}}}",
  "\\relPCS": "{\\relation_{\\mathsf{PCD},#1}}",
  "\\relIPA": "{\\relation_{\\mathsf{IPA},#1}}",
  "\\langPCS": "{\\language_{\\mathsf{PCD},#1}}",
  "\\rounds": "{k}",
  "\\degree": "{d}",
  "\\and": "{\\small \\mathsf{AND}}",
  "\\xor": "{\\small \\mathsf{XOR}}",
  "\\inv": "{\\small \\mathsf{INV}}",
  "\\sC": "{\\small \\mathsf{C}}",
  "\\sI": "{\\small \\mathsf{I}}",
  "\\sH": "{\\small \\mathsf{H}}",
  "\\sX": "{\\small \\mathsf{X}}",
  "\\sY": "{\\small \\mathsf{Y}}",
  "\\S": "{\\small S}",
  "\\G": "{\\small G}",
  "\\R": "{\\small R}",
  "\\T": "{\\small T}",
  "\\bF": "{\\small \\mathbb{F}}",
  "\\bG": "{\\small \\mathbb{G}}",
  "\\lsb": "{\\small \\mathsf{LSB}}",
  "\\sha": "{\\small\\mathsf{SHA}256}",
  "\\aes": "{\\small \\mathsf{AES}}",
  "\\gc": "{\\small \\mathcal{GC}}",
  "\\bit": "{\\{0,1\\}}",
  "\\zero": "{\\color{red}{0}}",
  "\\one": "{\\color{blue}{1}}",
  "\\enc": "{\\small \\mathsf{Enc}}",
  "\\gid": "{\\mathsf{gid}}",
  "\\counter": "{\\mathsf{counter}}",
  "\\prg": "{\\small \\mathsf{PRG}}",
  "\\plonk": "\\mathcal{PlonK}",
  "\\plookup": "\\textsf{Plookup}",
};

const config: Config = {
  title: "Mina book",
  tagline: "Cryptographic documentation and specifications for Mina",
  favicon: "img/favicon.ico",

  url: "https://o1-labs.github.io",
  baseUrl: "/proof-systems/",

  organizationName: "o1-labs",
  projectName: "proof-systems",

  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  markdown: {
    mermaid: true,
    format: "detect",
    parseFrontMatter: async (params) => {
      const result = await params.defaultParseFrontMatter(params);
      return result;
    },
    hooks: {
      onBrokenMarkdownLinks: "throw",
    },
  },

  themes: ["@docusaurus/theme-mermaid"],

  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          editUrl:
            "https://github.com/o1-labs/proof-systems/tree/master/book/",
          remarkPlugins: [remarkMath],
          rehypePlugins: [
            [
              rehypeKatex,
              {
                macros: katexMacros,
                throwOnError: true,
                strict: false,
                errorColor: "#cc0000",
              },
            ],
          ],
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  stylesheets: [
    {
      href: "https://cdn.jsdelivr.net/npm/katex@0.16.11/dist/katex.min.css",
      type: "text/css",
      crossorigin: "anonymous",
    },
  ],

  themeConfig: {
    navbar: {
      title: "Mina book",
      items: [
        {
          href: "https://o1-labs.github.io/proof-systems/rustdoc/",
          label: "Rust Docs",
          position: "right",
        },
        {
          href: "https://github.com/o1-labs/proof-systems",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Documentation",
          items: [
            {
              label: "Introduction",
              to: "/",
            },
            {
              label: "Rust Documentation",
              href: "https://o1-labs.github.io/proof-systems/rustdoc/",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "Mina Protocol",
              href: "https://minaprotocol.com/",
            },
            {
              label: "Discord",
              href: "https://discord.gg/minaprotocol",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/o1-labs/proof-systems",
            },
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} o1Labs. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["rust", "python", "bash"],
    },
    mermaid: {
      theme: { light: "default", dark: "dark" },
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
