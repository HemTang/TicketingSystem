// Import Joi
import Joi from "joi";
import AppError from "./apperror.js";

// Define the Joi schema

const validateData = (req, res, next) => {
  const ticketSchema = Joi.object({
    title: Joi.string().trim().min(3).max(100).required().messages({
      "string.empty": "Title is required",
      "string.min": "Title should be at least 3 characters",
      "string.max": "Title should be less than or equal to 100 characters",
    }),
    description: Joi.string().trim().min(10).max(1000).required().messages({
      "string.empty": "Description is required",
      "string.min": "Description should be at least 10 characters",
      "string.max":
        "Description should be less than or equal to 1000 characters",
    }),
    priority: Joi.string().valid("Low", "Medium", "High").required().messages({
      "any.only": "Priority must be one of Low, Medium, or High",
      "any.required": "Priority is required",
    }),
    category: Joi.string()
      .valid("Hardware", "Software", "Network")
      .required()
      .messages({
        "any.only": "Category must be one of Hardware, Software, or Network",
        "any.required": "Category is required",
      }),

    incidentfor: Joi.string().trim().min(3).max(100).required().messages({
      "string.empty": "Incident for is required",
      "string.min": "Incident for should be at least 3 characters",
      "string.max":
        "Incident for should be less than or equal to 100 characters",
    }),
  });
  const { error } = ticketSchema.validate(req.body);

  // If validation fails, throw a custom error
  if (error) {
    return next(new AppError(error.details[0].message, 400)); // 400 Bad Request
  } else {
    next();
  }
};

export default validateData;
