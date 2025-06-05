/*
  Warnings:

  - Added the required column `summary` to the `Donation` table without a default value. This is not possible if the table is not empty.

*/
-- First, add the new column as nullable
ALTER TABLE "Donation" ADD COLUMN "summary_new" DOUBLE PRECISION;

-- Update existing records to convert string summary to float
UPDATE "Donation"
SET "summary_new" = CAST(REGEXP_REPLACE("summary", '[^0-9.]', '', 'g') AS DOUBLE PRECISION)
WHERE "summary" IS NOT NULL;

-- Drop the old column
ALTER TABLE "Donation" DROP COLUMN "summary";

-- Rename the new column
ALTER TABLE "Donation" RENAME COLUMN "summary_new" TO "summary";

-- Make the column required
ALTER TABLE "Donation" ALTER COLUMN "summary" SET NOT NULL;
