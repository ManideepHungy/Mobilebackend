/*
  Warnings:

  - A unique constraint covering the columns `[name,organizationId]` on the table `Module` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `organizationId` to the `Module` table without a default value. This is not possible if the table is not empty.

*/
-- DropIndex
DROP INDEX "Module_name_key";

-- AlterTable
ALTER TABLE "Module" ADD COLUMN     "organizationId" INTEGER;

-- Update existing modules to belong to the first organization (Fredericton Community Kitchen)
UPDATE "Module" SET "organizationId" = (SELECT id FROM "Organization" WHERE name = 'Fredericton Community Kitchen' LIMIT 1);

-- Make organizationId NOT NULL after updating existing records
ALTER TABLE "Module" ALTER COLUMN "organizationId" SET NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "Module_name_organizationId_key" ON "Module"("name", "organizationId");

-- AddForeignKey
ALTER TABLE "Module" ADD CONSTRAINT "Module_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
