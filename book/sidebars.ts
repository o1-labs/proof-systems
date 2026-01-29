import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    "introduction",
    {
      type: "category",
      label: "Foundations",
      items: [
        "fundamentals/zkbook_foundations",
        "fundamentals/zkbook_groups",
        "fundamentals/zkbook_rings",
        "fundamentals/zkbook_fields",
        {
          type: "category",
          label: "Polynomials",
          link: {
            type: "doc",
            id: "fundamentals/zkbook_polynomials",
          },
          items: [
            "fundamentals/zkbook_multiplying_polynomials",
            "fundamentals/zkbook_fft",
          ],
        },
      ],
    },
    {
      type: "category",
      label: "Cryptographic Tools",
      items: [
        "fundamentals/zkbook_commitment",
        {
          type: "category",
          label: "Polynomial Commitments",
          link: {
            type: "doc",
            id: "plonk/polynomial_commitments",
          },
          items: ["plonk/inner_product", "plonk/inner_product_api"],
        },
        {
          type: "category",
          label: "Two Party Computation",
          link: {
            type: "doc",
            id: "fundamentals/zkbook_2pc/overview",
          },
          items: [
            {
              type: "category",
              label: "Garbled Circuits",
              link: {
                type: "doc",
                id: "fundamentals/zkbook_2pc/gc",
              },
              items: [
                "fundamentals/zkbook_2pc/basics",
                "fundamentals/zkbook_2pc/pap",
                "fundamentals/zkbook_2pc/freexor",
                "fundamentals/zkbook_2pc/row_red",
                "fundamentals/zkbook_2pc/halfgate",
                "fundamentals/zkbook_2pc/fulldesc",
                "fundamentals/zkbook_2pc/fkaes",
              ],
            },
            {
              type: "category",
              label: "Oblivious Transfer",
              link: {
                type: "doc",
                id: "fundamentals/zkbook_2pc/ot",
              },
              items: [
                "fundamentals/zkbook_2pc/baseot",
                "fundamentals/zkbook_2pc/ote",
              ],
            },
            "fundamentals/zkbook_2pc/2pc",
          ],
        },
        {
          type: "category",
          label: "Proof Systems",
          link: {
            type: "doc",
            id: "fundamentals/proof_systems",
          },
          items: ["fundamentals/zkbook_plonk"],
        },
      ],
    },
    {
      type: "category",
      label: "Background on PLONK",
      items: [
        {
          type: "category",
          label: "Overview",
          link: {
            type: "doc",
            id: "plonk/overview",
          },
          items: ["plonk/glossary"],
        },
        "plonk/domain",
        "plonk/lagrange",
        "plonk/fiat_shamir",
        "plonk/plookup",
        "plonk/maller",
        "plonk/zkpm",
      ],
    },
    {
      type: "category",
      label: "Kimchi",
      items: [
        "kimchi/overview",
        "kimchi/arguments",
        "kimchi/final_check",
        "kimchi/maller_15",
        {
          type: "category",
          label: "Lookup Tables",
          link: {
            type: "doc",
            id: "kimchi/lookup",
          },
          items: ["kimchi/extended-lookup-tables"],
        },
        "kimchi/custom_constraints",
        {
          type: "category",
          label: "Custom Gates",
          link: {
            type: "doc",
            id: "kimchi/gates",
          },
          items: [
            "kimchi/foreign_field_add",
            "kimchi/foreign_field_mul",
            "kimchi/keccak",
          ],
        },
      ],
    },
    {
      type: "category",
      label: "Pickles & Inductive Proof Systems",
      items: [
        "pickles/overview",
        "pickles/zkbook_ips",
        "pickles/accumulation",
        "pickles/deferred",
        "pickles/diagrams",
      ],
    },
    {
      type: "category",
      label: "Technical Specifications",
      items: [
        "specs/poseidon",
        "specs/poly-commitment",
        "specs/pasta",
        "specs/kimchi",
        "specs/urs",
        "specs/pickles",
        "specs/consensus",
      ],
    },
  ],
};

export default sidebars;
