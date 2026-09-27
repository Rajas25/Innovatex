# InnovateX

> A central repository for innovative software solutions, AI-driven applications, and intelligent automation systems.

InnovateX is a collection of projects focused on solving real-world problems through **Artificial Intelligence, Computer Vision, OCR, automation, and modern software technologies**.

---

## 📂 Projects

### 📄 AI Document & Identity Screening System

An AI-assisted document screening system designed to analyze identity documents, extract information, validate document data, detect potential image manipulation, perform facial verification, and generate a risk-based screening result.

📁 **Project Path:** `./AI-Document-Screening-System`

### 🔍 Key Features

- 📄 **Document Upload & Camera Input**
  - Upload or capture identity documents.
  - Supports document images such as Aadhaar, Passport, and Visa.

- 🔤 **OCR-Based Text Extraction**
  - Extracts text and relevant information from document images.
  - Uses Optical Character Recognition (OCR) for automated document analysis.

- 🪪 **Document Classification**
  - Identifies the type of submitted document.
  - Supports document classification based on extracted information.

- ✅ **Document Validation**
  - Validates extracted identity information.
  - Performs Aadhaar checksum validation using the Verhoeff algorithm.

- 🛡️ **Tampering & Image Integrity Analysis**
  - Performs image integrity analysis.
  - Examines metadata and uses Error Level Analysis (ELA) as a screening indicator for possible manipulation.

- 👤 **Face Detection & Verification**
  - Extracts the portrait from the identity document.
  - Compares the document portrait with the passenger photograph.
  - Generates a similarity-based biometric screening result.

- 📊 **Risk Scoring**
  - Combines results from document validation, biometric verification, metadata analysis, and image integrity checks.
  - Generates a risk score and risk level.

- 📝 **Audit Trail**
  - Records screening results and important processing information.
  - Provides an exportable audit log for review.

- 🖥️ **Interactive Web Interface**
  - Built using Streamlit.
  - Provides an easy-to-use interface for document screening and result visualization.

---

## 🏗️ System Workflow

```text
                 ┌─────────────────────┐
                 │  Document + Photo   │
                 │       Input         │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Image Preprocessing │
                 │     & Orientation   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │        OCR          │
                 │  Text Extraction    │
                 └──────────┬──────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
     ┌─────────────────┐        ┌─────────────────┐
     │    Document     │        │    Document     │
     │    Validation   │        │    Integrity     │
     └────────┬────────┘        └────────┬────────┘
              │                          │
              └─────────────┬────────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Face Verification   │
                 │ Document vs Person  │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    Risk Engine      │
                 │  Weighted Scoring   │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Screening Result   │
                 │ Risk Level + Action │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │    Audit Trail      │
                 └─────────────────────┘
