/*
  Warnings:

  - Added the required column `email` to the `Organization` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('PENDING', 'APPROVED', 'DENIED');

-- CreateEnum
CREATE TYPE "RegistrationType" AS ENUM ('ADULT', 'MINOR');

-- CreateEnum
CREATE TYPE "AgeBracket" AS ENUM ('UNDER_16', 'AGE_16_29', 'AGE_30_39', 'AGE_40_49', 'AGE_50_59', 'AGE_60_69', 'AGE_70_PLUS');

-- CreateEnum
CREATE TYPE "Pronouns" AS ENUM ('HE_HIM', 'SHE_HER', 'THEY_THEM', 'PREFER_NOT_TO_SAY');

-- CreateEnum
CREATE TYPE "CommunicationPreference" AS ENUM ('EMAIL', 'SMS', 'APP_NOTIFICATION');

-- CreateEnum
CREATE TYPE "Frequency" AS ENUM ('WEEKLY', 'BI_WEEKLY', 'MONTHLY', 'DAILY', 'ONCE', 'WHEN_TIME_PERMITS');

-- CreateEnum
CREATE TYPE "HowDidYouHear" AS ENUM ('FAMILY_FRIENDS', 'GOOGLE', 'SOCIAL_MEDIA', 'CONNECT_FREDERICTON', 'SCHOOL', 'WORK', 'NOTICE_BOARDS', 'EVENTS');

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "email" TEXT NOT NULL,
ADD COLUMN     "incoming_dollar_value" DOUBLE PRECISION DEFAULT 10;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "address" TEXT,
ADD COLUMN     "ageBracket" TEXT,
ADD COLUMN     "allergies" TEXT,
ADD COLUMN     "approvedAt" TIMESTAMP(3),
ADD COLUMN     "approvedBy" INTEGER,
ADD COLUMN     "birthdate" TIMESTAMP(3),
ADD COLUMN     "canCallIfShortHanded" BOOLEAN DEFAULT true,
ADD COLUMN     "city" TEXT,
ADD COLUMN     "communicationPreferences" TEXT,
ADD COLUMN     "denialReason" TEXT,
ADD COLUMN     "deniedAt" TIMESTAMP(3),
ADD COLUMN     "deniedBy" INTEGER,
ADD COLUMN     "emergencyContactName" TEXT,
ADD COLUMN     "emergencyContactNumber" TEXT,
ADD COLUMN     "frequency" TEXT,
ADD COLUMN     "homePhone" TEXT,
ADD COLUMN     "howDidYouHear" TEXT,
ADD COLUMN     "medicalConcerns" TEXT,
ADD COLUMN     "parentGuardianEmail" TEXT,
ADD COLUMN     "parentGuardianName" TEXT,
ADD COLUMN     "postalCode" TEXT,
ADD COLUMN     "preferredDays" TEXT,
ADD COLUMN     "preferredPrograms" TEXT,
ADD COLUMN     "preferredShifts" TEXT,
ADD COLUMN     "profilePictureUrl" TEXT,
ADD COLUMN     "pronouns" TEXT,
ADD COLUMN     "registrationType" "RegistrationType" DEFAULT 'ADULT',
ADD COLUMN     "requiredHours" INTEGER,
ADD COLUMN     "schoolWorkCommitment" BOOLEAN DEFAULT false,
ADD COLUMN     "startDate" TIMESTAMP(3),
ADD COLUMN     "status" "UserStatus" NOT NULL DEFAULT 'PENDING';

-- CreateTable
CREATE TABLE "WeighingCategory" (
    "id" SERIAL NOT NULL,
    "organizationId" INTEGER NOT NULL,
    "kilogram(kg)" DOUBLE PRECISION NOT NULL,
    "pound(lb)" DOUBLE PRECISION NOT NULL,
    "category" TEXT NOT NULL,

    CONSTRAINT "WeighingCategory_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Module" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,

    CONSTRAINT "Module_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserModulePermission" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "organizationId" INTEGER NOT NULL,
    "moduleId" INTEGER NOT NULL,
    "canAccess" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "UserModulePermission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TermsAndConditions" (
    "id" SERIAL NOT NULL,
    "organizationId" INTEGER NOT NULL,
    "version" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "fileUrl" TEXT NOT NULL,
    "fileName" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdBy" INTEGER,

    CONSTRAINT "TermsAndConditions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserAgreement" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "organizationId" INTEGER NOT NULL,
    "termsAndConditionsId" INTEGER NOT NULL,
    "signature" TEXT NOT NULL,
    "signedDocumentUrl" TEXT,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ipAddress" TEXT,
    "userAgent" TEXT,

    CONSTRAINT "UserAgreement_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "WeighingCategory_category_organizationId_key" ON "WeighingCategory"("category", "organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Module_name_key" ON "Module"("name");

-- CreateIndex
CREATE UNIQUE INDEX "UserModulePermission_userId_organizationId_moduleId_key" ON "UserModulePermission"("userId", "organizationId", "moduleId");

-- CreateIndex
CREATE UNIQUE INDEX "TermsAndConditions_organizationId_version_key" ON "TermsAndConditions"("organizationId", "version");

-- CreateIndex
CREATE UNIQUE INDEX "UserAgreement_userId_organizationId_termsAndConditionsId_key" ON "UserAgreement"("userId", "organizationId", "termsAndConditionsId");

-- AddForeignKey
ALTER TABLE "WeighingCategory" ADD CONSTRAINT "WeighingCategory_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE NO ACTION ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "UserModulePermission" ADD CONSTRAINT "UserModulePermission_moduleId_fkey" FOREIGN KEY ("moduleId") REFERENCES "Module"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserModulePermission" ADD CONSTRAINT "UserModulePermission_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TermsAndConditions" ADD CONSTRAINT "TermsAndConditions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAgreement" ADD CONSTRAINT "UserAgreement_termsAndConditionsId_fkey" FOREIGN KEY ("termsAndConditionsId") REFERENCES "TermsAndConditions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserAgreement" ADD CONSTRAINT "UserAgreement_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
